#!/usr/bin/env python3
"""Reconstruct and cross-check the ordered APT29 sequence in MITRE result JSON.

This script audits the sequence reconstruction only. It does not reproduce the
paper's synthetic generator, Markov/LSTM training, clustering baseline, or scores.

Example:
  python scripts/reconstruct_apt29_sequence.py \\
    --input data/McAfee.1.APT29.1_Results.json \\
    --input data/Microsoft.1.APT29.1_Results.json \\
    --input data/FireEye.1.APT29.1_Results.json \\
    --input data/CrowdStrike.1.APT29.1_Results.json \\
    --input data/Bitdefender.1.APT29.1_Results.json \\
    --outdir artifacts
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path
from typing import Any

SUBSTEP_RE = re.compile(r"^(?P<step>\d+)(?:\.(?P<branch>[A-Z]))?(?:\.(?P<order>\d+))?$")
# Immutable repository revision verified to contain all five result files.
SOURCE_COMMIT = "8bee0d3128abc08c4e00c60b01c1608e162bb9ce"
DEFAULT_REPOSITORY = f"https://github.com/mitre-attack/joystick/tree/{SOURCE_COMMIT}/data/evaluations/apt29"
VENDOR_FILES = [
    "McAfee.1.APT29.1_Results.json",
    "Microsoft.1.APT29.1_Results.json",
    "FireEye.1.APT29.1_Results.json",
    "CrowdStrike.1.APT29.1_Results.json",
    "Bitdefender.1.APT29.1_Results.json",
]
RAW_BASE = f"https://raw.githubusercontent.com/mitre-attack/joystick/{SOURCE_COMMIT}/data/evaluations/apt29"
EXPECTED_GIT_BLOB_SHA1 = {
    "McAfee.1.APT29.1_Results.json": "369ee8151f516fa56b9935e3710aae6c1ddb0561",
    "Microsoft.1.APT29.1_Results.json": "6f69ec6148d47da4087bc0a27b702a25607fedfa",
    "FireEye.1.APT29.1_Results.json": "c2af8b2fea8255a43800bad6ef7d53295be0df90",
    "CrowdStrike.1.APT29.1_Results.json": "6fc22d773238a9a8df645143d76b0a1f1d55dcaf",
    "Bitdefender.1.APT29.1_Results.json": "5cefb66b039ac70af5edcc211f48a24203df617f",
}


def git_blob_sha1(data: bytes) -> str:
    """Compute Git's blob object SHA-1, including the canonical object header."""
    import hashlib
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def download_vendor_files(directory: Path) -> list[Path]:
    """Download the five public result JSON files from the MITRE repository."""
    directory.mkdir(parents=True, exist_ok=True)
    paths = []
    for filename in VENDOR_FILES:
        url = f"{RAW_BASE}/{filename}"
        target = directory / filename
        request = urllib.request.Request(url, headers={"User-Agent": "ICRFCS-Sequence-Reconstruction-Audit/1.0"})
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                data = response.read()
        except Exception as exc:
            raise ReconstructionError(f"Could not download {url}: {exc}") from exc
        # Validate JSON before leaving a corrupted/HTML error page on disk.
        try:
            json.loads(data.decode("utf-8"))
        except Exception as exc:
            raise ReconstructionError(f"Downloaded content from {url} was not valid UTF-8 JSON") from exc
        actual_git_blob_sha1 = git_blob_sha1(data)
        expected_git_blob_sha1 = EXPECTED_GIT_BLOB_SHA1[filename]
        if actual_git_blob_sha1 != expected_git_blob_sha1:
            raise ReconstructionError(
                f"Pinned source mismatch for {filename}: expected Git blob SHA-1 "
                f"{expected_git_blob_sha1}, got {actual_git_blob_sha1}"
            )
        target.write_bytes(data)
        paths.append(target)
    return paths


class ReconstructionError(ValueError):
    """Raised when the source JSON cannot be reconstructed unambiguously."""


def _parse_substep(value: Any) -> tuple[int, str, int]:
    if not isinstance(value, str):
        raise ReconstructionError(f"SubStep must be a string, got {value!r}")
    match = SUBSTEP_RE.fullmatch(value.strip())
    if not match:
        raise ReconstructionError(f"Unrecognized SubStep format: {value!r}")
    return int(match.group("step")), match.group("branch") or "", int(match.group("order") or 0)


def reconstruct(path: Path) -> list[dict[str, Any]]:
    """Flatten and sort the technique/step records from one public result JSON."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReconstructionError(f"Cannot read valid JSON from {path}: {exc}") from exc

    techniques = payload.get("Techniques")
    if not isinstance(techniques, list):
        raise ReconstructionError(f"{path}: expected top-level 'Techniques' list")

    records: list[dict[str, Any]] = []
    for technique in techniques:
        if not isinstance(technique, dict):
            raise ReconstructionError(f"{path}: non-object item in Techniques")
        technique_id = technique.get("TechniqueId")
        technique_name = technique.get("TechniqueName")
        steps = technique.get("Steps", [])
        if not technique_id or not isinstance(steps, list):
            raise ReconstructionError(f"{path}: missing TechniqueId or Steps list")
        tactics = [t.get("TacticName", "") for t in technique.get("Tactics", []) if isinstance(t, dict)]
        for step in steps:
            if not isinstance(step, dict):
                raise ReconstructionError(f"{path}: non-object item inside Steps")
            substep = step.get("SubStep")
            if not substep:
                # Records without a substep cannot be put in the ordered sequence.
                continue
            major, branch, order = _parse_substep(substep)
            records.append({
                "substep": substep,
                "_major": major,
                "_branch": branch,
                "_order": order,
                "technique_id": technique_id,
                "technique_name": technique_name,
                "tactics": tactics,
            })

    if not records:
        raise ReconstructionError(f"{path}: no step records with SubStep labels found")

    records.sort(key=lambda r: (r["_major"], r["_branch"], r["_order"]))
    substeps = [r["substep"] for r in records]
    duplicates = sorted({s for s in substeps if substeps.count(s) > 1})
    if duplicates:
        raise ReconstructionError(f"{path}: duplicate SubStep labels: {duplicates[:10]}")

    clean: list[dict[str, Any]] = []
    for index, record in enumerate(records, start=1):
        clean.append({
            "index": index,
            "substep": record["substep"],
            "technique_id": record["technique_id"],
            "technique_name": record["technique_name"],
            "tactics": record["tactics"],
        })
    return clean


def signature(records: list[dict[str, Any]]) -> list[tuple[str, str]]:
    return [(row["substep"], row["technique_id"]) for row in records]


def first_differences(left: list[dict[str, Any]], right: list[dict[str, Any]], limit: int = 8) -> list[dict[str, Any]]:
    diffs: list[dict[str, Any]] = []
    width = max(len(left), len(right))
    for i in range(width):
        a = left[i] if i < len(left) else None
        b = right[i] if i < len(right) else None
        if a is None or b is None or (a["substep"], a["technique_id"]) != (b["substep"], b["technique_id"]):
            diffs.append({"index": i + 1, "reference": None if a is None else {"substep": a["substep"], "technique_id": a["technique_id"]},
                          "comparison": None if b is None else {"substep": b["substep"], "technique_id": b["technique_id"]}})
            if len(diffs) >= limit:
                break
    return diffs


def audit(paths: list[Path]) -> dict[str, Any]:
    if not paths:
        raise ReconstructionError("Provide at least one --input JSON file")
    reconstructed = [(p, reconstruct(p)) for p in paths]
    reference_path, reference_sequence = reconstructed[0]
    reference_signature = signature(reference_sequence)
    sources = []
    all_equal = True
    for path, sequence in reconstructed:
        matches = signature(sequence) == reference_signature
        all_equal = all_equal and matches
        raw_bytes = path.read_bytes()
        actual_git_blob_sha1 = git_blob_sha1(raw_bytes)
        expected_git_blob_sha1 = EXPECTED_GIT_BLOB_SHA1.get(path.name)
        sources.append({
            "file": path.name,
            "git_blob_sha1": actual_git_blob_sha1,
            "matches_pinned_source_revision": (actual_git_blob_sha1 == expected_git_blob_sha1) if expected_git_blob_sha1 else None,
            "sequence_instances": len(sequence),
            "unique_substeps": len({row["substep"] for row in sequence}),
            "unique_technique_ids": len({row["technique_id"] for row in sequence}),
            "matches_reference_ordered_substep_technique_pairs": matches,
            "first_differences_vs_reference": [] if matches else first_differences(reference_sequence, sequence),
        })
    return {
        "purpose": "Sequence reconstruction and cross-vendor data-integrity audit only; this is not a model-results reproduction.",
        "public_source_repository": DEFAULT_REPOSITORY,
        "sorting_rule": "Flatten Techniques[].Steps[]; sort by numeric major step, branch letter, numeric suborder in SubStep.",
        "signature_fields": ["substep", "technique_id"],
        "reference_file": reference_path.name,
        "cross_vendor_pairwise_identity_to_reference": all_equal,
        "source_files": sources,
        "sequence": reference_sequence,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", action="append", type=Path, default=[], help="Path to one MITRE APT29 vendor result JSON; repeat for comparison.")
    parser.add_argument("--download-mitre-five-vendors", action="store_true", help="Download the five referenced public JSON files (requires internet access).")
    parser.add_argument("--data-dir", type=Path, default=Path("data"), help="Directory for downloaded public JSON files.")
    parser.add_argument("--outdir", type=Path, default=Path("artifacts"), help="Directory for sequence and audit JSON/TXT outputs.")
    args = parser.parse_args()
    inputs = list(args.input)
    try:
        if args.download_mitre_five_vendors:
            inputs.extend(download_vendor_files(args.data_dir))
        result = audit(inputs)
    except ReconstructionError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    args.outdir.mkdir(parents=True, exist_ok=True)
    sequence_file = args.outdir / "apt29_reconstructed_sequence.json"
    audit_file = args.outdir / "apt29_cross_vendor_audit.json"
    summary_file = args.outdir / "apt29_cross_vendor_audit.txt"
    sequence_file.write_text(json.dumps(result["sequence"], indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    summary = {k: v for k, v in result.items() if k != "sequence"}
    audit_file.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    lines = [
        "APT29 ordered-sequence reconstruction audit",
        f"Public source: {DEFAULT_REPOSITORY}",
        f"Sorting rule: {result['sorting_rule']}",
        f"Reference file: {result['reference_file']}",
        f"All files match reference ordered (SubStep, TechniqueId) pairs: {result['cross_vendor_pairwise_identity_to_reference']}",
        "",
    ]
    for source in result["source_files"]:
        lines.append(f"{source['file']}: instances={source['sequence_instances']}; unique_substeps={source['unique_substeps']}; unique_technique_ids={source['unique_technique_ids']}; match={source['matches_reference_ordered_substep_technique_pairs']}")
        if source["first_differences_vs_reference"]:
            lines.append(f"  First differences: {source['first_differences_vs_reference']}")
    lines += ["", "Interpretation: matching vendor result files support reconstruction consistency, but they represent the same emulation flow and are not independent campaign samples.",
              "This script does not validate the published top-k scores, clustering ranking policy, generator counts, or model training results."]
    summary_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("Wrote:", sequence_file)
    print("Wrote:", audit_file)
    print("Wrote:", summary_file)
    print(lines[5] if len(lines) > 5 else "")
    return 0 if result["cross_vendor_pairwise_identity_to_reference"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
