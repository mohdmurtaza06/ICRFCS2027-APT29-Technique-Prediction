#!/usr/bin/env python3
"""Summarize comparable benchmark conditions from reconciled run directories.

Example:
  python scripts/summarize_conditions.py \
    --condition primary=artifacts_env_rerun_reflect \
    --condition clamp=artifacts_env_rerun_clamp \
    --condition uniform_tactic=artifacts_sensitivity_uniform_tactic \
    --condition active_only=artifacts_sensitivity_active_only \
    --out audit/sensitivity_comparison.json

The script requires matching seed sets, target counts, environment, core model
settings, and input hashes. It summarizes mean accuracy and seed dispersion on
the same dependent target positions; it does not interpret seeds as campaigns.
"""
from __future__ import annotations
import argparse
import json
import statistics
import sys
from pathlib import Path
from typing import Any

METHODS = ("frequency", "cooccurrence", "markov1", "markov2_backoff", "lstm")
KS = (1, 3, 5)


def _load_condition(label: str, path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    manifest_path = path / "run_manifest.json"
    metrics_path = path / "metrics_by_seed.json"
    if not manifest_path.is_file() or not metrics_path.is_file():
        raise ValueError(f"{label}: expected run_manifest.json and metrics_by_seed.json in {path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    if not metrics:
        raise ValueError(f"{label}: metrics_by_seed.json is empty")
    for seed, seed_metrics in metrics.items():
        for method in METHODS:
            for k in KS:
                key = f"{method}_top{k}"
                item = seed_metrics.get(key)
                if not isinstance(item, dict) or item.get("n") != manifest.get("test_positions"):
                    raise ValueError(f"{label} seed {seed}: malformed/mismatched metric {key}")
                if item.get("hits") is None or not 0 <= int(item["hits"]) <= int(item["n"]):
                    raise ValueError(f"{label} seed {seed}: invalid hits for {key}")
    return manifest, metrics


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--condition", action="append", required=True, metavar="LABEL=DIR",
                        help="condition label and path; repeat for each condition")
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args()

    conditions: dict[str, tuple[dict[str, Any], dict[str, Any], Path]] = {}
    try:
        for spec in args.condition:
            if "=" not in spec:
                raise ValueError(f"Malformed condition {spec!r}; expected LABEL=DIR")
            label, raw_path = spec.split("=", 1)
            if not label or label in conditions:
                raise ValueError(f"Empty or repeated condition label: {label!r}")
            path = Path(raw_path)
            manifest, metrics = _load_condition(label, path)
            conditions[label] = (manifest, metrics, path)
        if len(conditions) < 2:
            raise ValueError("At least two conditions are required")

        baseline_label = next(iter(conditions))
        baseline_manifest = conditions[baseline_label][0]
        baseline_metrics = conditions[baseline_label][1]
        reference = {
            "seeds": sorted(baseline_metrics, key=lambda x: int(x)),
            "test_positions": baseline_manifest.get("test_positions"),
            "context_positions": baseline_manifest.get("context_positions"),
            "python_and_package_versions": baseline_manifest.get("python_and_package_versions"),
            "script_hashes": baseline_manifest.get("script_hashes"),
            "source_hashes": baseline_manifest.get("source_hashes"),
            "candidate_vocabulary_size": baseline_manifest.get("candidate_vocabulary_size"),
            "sequence_length": baseline_manifest.get("sequence_length"),
            "lstm_epochs": baseline_manifest.get("configuration", {}).get("lstm_epochs"),
            "lstm_window_size": baseline_manifest.get("configuration", {}).get("lstm_window_size"),
            "synthetic_sequences_per_seed": baseline_manifest.get("configuration", {}).get("synthetic_sequences_per_seed"),
        }
        summaries: dict[str, Any] = {}
        for label, (manifest, metrics, path) in conditions.items():
            checks = {
                "seeds": sorted(metrics, key=lambda x: int(x)),
                "test_positions": manifest.get("test_positions"),
                "context_positions": manifest.get("context_positions"),
                "python_and_package_versions": manifest.get("python_and_package_versions"),
                "script_hashes": manifest.get("script_hashes"),
                "source_hashes": manifest.get("source_hashes"),
                "candidate_vocabulary_size": manifest.get("candidate_vocabulary_size"),
                "sequence_length": manifest.get("sequence_length"),
                "lstm_epochs": manifest.get("configuration", {}).get("lstm_epochs"),
                "lstm_window_size": manifest.get("configuration", {}).get("lstm_window_size"),
                "synthetic_sequences_per_seed": manifest.get("configuration", {}).get("synthetic_sequences_per_seed"),
            }
            mismatches = [key for key, val in reference.items() if checks[key] != val]
            if mismatches:
                raise ValueError(f"Condition {label} is not directly comparable to {baseline_label}; mismatches: {mismatches}")
            reconciliation_path = path / "reconciliation.json"
            if not reconciliation_path.is_file():
                raise ValueError(f"{label}: missing independent reconciliation.json")
            reconciliation = json.loads(reconciliation_path.read_text(encoding="utf-8"))
            if not reconciliation.get("all_checks_passed"):
                raise ValueError(f"{label}: independent reconciliation did not pass")

            method_summary: dict[str, Any] = {}
            for method in METHODS:
                method_summary[method] = {}
                for k in KS:
                    key = f"{method}_top{k}"
                    hits_by_seed = {seed: metrics[seed][key]["hits"] for seed in sorted(metrics, key=lambda x: int(x))}
                    acc_pct = [100.0 * int(hits) / int(metrics[seed][key]["n"]) for seed, hits in hits_by_seed.items()]
                    method_summary[method][f"top{k}"] = {
                        "hits_by_seed_out_of_42": hits_by_seed,
                        "mean_accuracy_pct": statistics.mean(acc_pct),
                        "sample_sd_accuracy_percentage_points": statistics.stdev(acc_pct) if len(acc_pct) > 1 else 0.0,
                    }
            summaries[label] = {
                "run_directory": str(path),
                "generator_policy": manifest.get("configuration", {}),
                "reconciliation_passed": True,
                "methods": method_summary,
            }

        output = {
            "status": "PASS",
            "interpretation": "Descriptive sensitivity across three seeds evaluated on the same dependent 42-position suffix; seeds are not independent campaigns.",
            "comparability_checks": reference,
            "conditions": summaries,
        }
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    rendered = json.dumps(output, indent=2, ensure_ascii=False) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(rendered, encoding="utf-8")
    print(rendered)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
