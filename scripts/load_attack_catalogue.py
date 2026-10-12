#!/usr/bin/env python3
"""Load a pinned MITRE ATT&CK Enterprise STIX catalogue independently of test labels.

The versioned release is the only source of candidate technique IDs and tactic
mappings. No evaluation-sequence arguments are accepted by this module.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import urllib.request
from pathlib import Path
from typing import Any

CATALOGUE_NAME = "MITRE ATT&CK Enterprise"
CATALOGUE_VERSION = "18.1"
CATALOGUE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "v18.1/enterprise-attack/enterprise-attack-18.1.json"
)
USER_AGENT = "ICRFCS2027-TTP-Benchmark/1.0"
PHASE_LABELS = {
    "reconnaissance": "Reconnaissance",
    "resource-development": "Resource Development",
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read valid UTF-8 JSON from catalogue {path}: {exc}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("objects"), list):
        raise ValueError("ATT&CK catalogue must be a STIX bundle containing an objects list.")
    return payload


def download_catalogue(path: Path) -> None:
    """Download and validate the versioned source; write atomically after validation."""
    path.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(CATALOGUE_URL, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            raw = response.read()
    except Exception as exc:
        raise RuntimeError(f"Could not download pinned ATT&CK v{CATALOGUE_VERSION} catalogue: {exc}") from exc
    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise ValueError("Downloaded ATT&CK catalogue is not valid UTF-8 JSON.") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("objects"), list):
        raise ValueError("Downloaded content is not an ATT&CK STIX bundle with objects[].")
    _validate_release_metadata(payload)
    temp = path.with_suffix(path.suffix + ".part")
    temp.write_bytes(raw)
    temp.replace(path)


def _validate_release_metadata(payload: dict[str, Any]) -> None:
    """Fail closed when a local STIX bundle does not declare the expected release."""
    versions = {
        obj.get("x_mitre_version")
        for obj in payload.get("objects", [])
        if isinstance(obj, dict)
        and obj.get("type") == "x-mitre-collection"
        and obj.get("name") == "Enterprise ATT&CK"
        and isinstance(obj.get("x_mitre_version"), str)
    }
    if CATALOGUE_VERSION not in versions:
        rendered = sorted(str(version) for version in versions)
        raise ValueError(
            f"Expected MITRE ATT&CK Enterprise v{CATALOGUE_VERSION} collection metadata; "
            f"found {rendered or 'no Enterprise ATT&CK collection version'}"
        )


def load_catalogue(path: Path, download_if_missing: bool = True):
    """Return (sorted technique IDs, tactic_map, metadata).

    Includes all technique IDs retained in this pinned release, including objects
    marked deprecated/revoked when still present, to support historic evaluation
    labels without consulting the target sequence. The status counts are recorded.
    """
    if not path.exists():
        if not download_if_missing:
            raise FileNotFoundError(path)
        download_catalogue(path)

    payload = _read_json(path)
    _validate_release_metadata(payload)
    raw = path.read_bytes()
    tactic_map: dict[str, set[str]] = {}
    status = {"active": 0, "deprecated": 0, "revoked": 0}

    for obj in payload["objects"]:
        if not isinstance(obj, dict) or obj.get("type") != "attack-pattern":
            continue
        refs = obj.get("external_references", [])
        if not isinstance(refs, list):
            continue
        technique_id = next(
            (
                ref.get("external_id")
                for ref in refs
                if isinstance(ref, dict)
                and ref.get("source_name") == "mitre-attack"
                and isinstance(ref.get("external_id"), str)
                and ref["external_id"].startswith("T")
            ),
            None,
        )
        if not technique_id:
            continue

        tactics: set[str] = set()
        phases = obj.get("kill_chain_phases", [])
        if isinstance(phases, list):
            for phase in phases:
                if not isinstance(phase, dict) or phase.get("kill_chain_name") != "mitre-attack":
                    continue
                label = PHASE_LABELS.get(phase.get("phase_name"))
                if label:
                    tactics.add(label)
        tactic_map.setdefault(technique_id, set()).update(tactics)
        if obj.get("revoked"):
            status["revoked"] += 1
        elif obj.get("x_mitre_deprecated"):
            status["deprecated"] += 1
        else:
            status["active"] += 1

    vocab = sorted(tactic_map)
    if not vocab:
        raise ValueError("Catalogue yielded no technique IDs; refusing to continue.")
    metadata = {
        "catalogue": CATALOGUE_NAME,
        "version": CATALOGUE_VERSION,
        "source_revision_tag": "v18.1",
        "source_url": CATALOGUE_URL,
        "local_file": str(path),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "technique_ids_in_candidate_universe": len(vocab),
        "technique_object_status_counts": status,
        "tactic_labels_found": sorted({t for tactics in tactic_map.values() for t in tactics}),
        "vocabulary_policy": (
            "Candidate vocabulary and tactic mapping derive only from the pinned ATT&CK catalogue, "
            "not the APT29 evaluation sequence. Deprecated/revoked technique objects are retained "
            "when still present in the pinned catalogue for historical-label coverage."
        ),
    }
    return vocab, tactic_map, metadata


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", type=Path, default=Path("data/enterprise-attack-18.1.json"))
    args = parser.parse_args()
    try:
        vocab, tactic_map, metadata = load_catalogue(args.path)
    except Exception as exc:
        parser.error(str(exc))
    print(json.dumps(metadata, indent=2))
    print("Vocabulary preview:", vocab[:10])
    print("Tactic mappings:", len(tactic_map))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
