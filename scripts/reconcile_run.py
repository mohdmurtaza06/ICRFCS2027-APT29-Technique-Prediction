"""Independent reconciliation of a benchmark run directory.

Re-derives everything it can WITHOUT importing run_benchmark.py:
  * source / catalogue SHA-256 hashes against the run manifest
  * the 98/42 split and the true labels in every prediction row
  * catalogue coverage of observed labels (read straight from the STIX JSON)
  * ranking validity: exactly 5 unique candidates, all inside the catalogue universe
  * Top-1/3/5 hits recomputed from the CSV rankings vs metrics_by_seed.json
  * per-seed hit counts and the seed-level mean table used in the manuscript

Usage:
  python scripts/reconcile_run.py --run-dir RUN --data-dir DATA [--out RECONCILIATION.json]
Exit code is non-zero if any check fails.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import statistics
import sys
from pathlib import Path

METHODS = ["frequency", "cooccurrence", "markov1", "markov2_backoff", "lstm"]
KS = (1, 3, 5)
CONTEXT, TEST = 98, 42


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def catalogue_universe(path: Path) -> set[str]:
    """Technique + sub-technique external IDs from the raw STIX bundle (all statuses)."""
    bundle = json.loads(path.read_text(encoding="utf-8"))
    ids: set[str] = set()
    for obj in bundle["objects"]:
        if obj.get("type") != "attack-pattern":
            continue
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and str(ref.get("external_id", "")).startswith("T"):
                ids.add(ref["external_id"])
    return ids


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", type=Path, required=True)
    ap.add_argument("--data-dir", type=Path, required=True)
    ap.add_argument("--out", type=Path, default=None)
    a = ap.parse_args()

    failures: list[str] = []

    def check(cond: bool, msg: str) -> None:
        if not cond:
            failures.append(msg)

    manifest = json.loads((a.run_dir / "run_manifest.json").read_text())
    metrics = json.loads((a.run_dir / "metrics_by_seed.json").read_text())
    seq_raw = json.loads((a.run_dir / "apt29_sequence.json").read_text())
    seq = [s if isinstance(s, str) else s.get("technique_id") or s.get("TechniqueId") for s in seq_raw]

    # 1. hashes
    for rec in manifest["source_hashes"]:
        p = a.data_dir / rec["file"]
        check(p.exists() and sha256(p) == rec["sha256"], f"hash mismatch: {rec['file']}")

    # 2. sequence/split
    check(len(seq) == CONTEXT + TEST, f"sequence length {len(seq)} != 140")
    target = seq[CONTEXT:]

    # 3. catalogue coverage (independent of the project loader)
    universe = catalogue_universe(a.data_dir / "enterprise-attack-18.1.json")
    check(len(universe) == manifest["candidate_vocabulary_size"],
          f"universe size {len(universe)} != manifest {manifest['candidate_vocabulary_size']}")
    missing = sorted(set(seq) - universe)
    check(not missing, f"observed labels missing from catalogue: {missing}")
    held_out_only = sorted(set(target) - set(seq[:CONTEXT]))

    report: dict = {
        "sequence_length": len(seq),
        "distinct_observed_labels": len(set(seq)),
        "catalogue_universe_size": len(universe),
        "observed_labels_missing_from_catalogue": missing,
        "heldout_labels_not_seen_in_context": held_out_only,
        "heldout_positions_whose_label_is_unseen_in_context": sum(1 for t in target if t not in set(seq[:CONTEXT])),
        "seeds": {},
    }

    # 4. per-seed row checks and recomputation
    summary: dict[str, dict[str, list[int]]] = {m: {f"top{k}": [] for k in KS} for m in METHODS}
    for seed in sorted(metrics):
        with (a.run_dir / f"predictions_seed_{seed}.csv").open(encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
        check(len(rows) == TEST, f"seed {seed}: {len(rows)} rows")
        hits = {m: {k: 0 for k in KS} for m in METHODS}
        for i, row in enumerate(rows):
            check(int(row["position"]) == i + 1 and int(row["sequence_index"]) == CONTEXT + i + 1,
                  f"seed {seed} row {i}: position/index wrong")
            check(row["true_technique_id"] == target[i], f"seed {seed} row {i}: true label != sequence[{CONTEXT + i}]")
            for m in METHODS:
                ranking = json.loads(row[f"{m}_top5"])
                check(len(ranking) == 5 and len(set(ranking)) == 5, f"seed {seed} row {i} {m}: not 5 unique")
                check(set(ranking) <= universe, f"seed {seed} row {i} {m}: candidate outside catalogue")
                for k in KS:
                    hits[m][k] += int(row["true_technique_id"] in ranking[:k])
        seed_rep = {}
        for m in METHODS:
            for k in KS:
                recorded = metrics[seed][f"{m}_top{k}"]["hits"] if f"{m}_top{k}" in metrics[seed] else None
                check(recorded == hits[m][k], f"seed {seed} {m} top{k}: recorded {recorded} != recomputed {hits[m][k]}")
                summary[m][f"top{k}"].append(hits[m][k])
            seed_rep[m] = [hits[m][k] for k in KS]
        report["seeds"][seed] = seed_rep

    report["mean_accuracy_pct"] = {
        m: {k: round(100 * statistics.mean(v) / TEST, 2) for k, v in d.items()} for m, d in summary.items()
    }
    report["sample_sd_accuracy_pct"] = {
        m: {k: round(100 * statistics.stdev(v) / TEST, 2) if len(v) > 1 else 0.0 for k, v in d.items()} for m, d in summary.items()
    }
    report["failures"] = failures
    report["all_checks_passed"] = not failures
    if a.out:
        a.out.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
