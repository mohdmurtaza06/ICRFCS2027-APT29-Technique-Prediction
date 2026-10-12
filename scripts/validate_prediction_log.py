#!/usr/bin/env python3
"""Recompute top-1/top-3/top-5 scores from per-position ranking logs.

Expected wide CSV columns: position,true_technique_id and, for each method,
<method>_top1 ... <method>_top5. See templates/prediction_log_template.csv.
This script validates logged predictions; it does not train or reproduce models.
"""
from __future__ import annotations
import argparse
import csv
import json
import sys
from collections import OrderedDict
from pathlib import Path
from typing import Any

METHODS = OrderedDict([
    ("global_frequency", "Global frequency"),
    ("cooccurrence_clustering", "Co-occurrence clustering"),
    ("markov2", "Markov (2nd-order)"),
    ("markov1", "Markov (1st-order)"),
    ("lstm_pretrain_finetune", "LSTM (pretrain + fine-tune)"),
    ("lstm_mixed", "LSTM (mixed training)"),
])
K_VALUES = (1, 3, 5)
EXPECTED_POSITIONS = 42


class PredictionLogError(ValueError):
    pass


def required_columns() -> list[str]:
    cols = ["position", "true_technique_id"]
    for method in METHODS:
        cols.extend(f"{method}_top{k}" for k in range(1, 6))
    return cols


def validate_and_score(path: Path, expected_positions: int = EXPECTED_POSITIONS) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            headers = reader.fieldnames or []
            missing = [c for c in required_columns() if c not in headers]
            if missing:
                raise PredictionLogError(f"Missing required columns: {missing}")
            rows = list(reader)
    except OSError as exc:
        raise PredictionLogError(f"Could not read {path}: {exc}") from exc

    if len(rows) != expected_positions:
        raise PredictionLogError(f"Expected {expected_positions} rows, found {len(rows)}")
    positions: list[int] = []
    for row_no, row in enumerate(rows, start=2):
        try:
            pos = int(row["position"])
        except (ValueError, TypeError):
            raise PredictionLogError(f"Row {row_no}: position must be an integer")
        positions.append(pos)
        if not (row.get("true_technique_id") or "").strip():
            raise PredictionLogError(f"Row {row_no}: true_technique_id is blank")
        for method in METHODS:
            ranked = [(row.get(f"{method}_top{k}") or "").strip() for k in range(1, 6)]
            if any(not item for item in ranked):
                raise PredictionLogError(f"Row {row_no}: incomplete top-5 ranking for {method}")
            if len(set(ranked)) != 5:
                raise PredictionLogError(f"Row {row_no}: duplicate candidates in {method} top-5 ranking")
    if sorted(positions) != list(range(1, expected_positions + 1)):
        raise PredictionLogError(f"Positions must be exactly 1..{expected_positions}; got {sorted(positions)}")
    rows.sort(key=lambda r: int(r["position"]))

    scores: dict[str, Any] = OrderedDict()
    for method, label in METHODS.items():
        counts = {}
        for k in K_VALUES:
            hits = sum(1 for row in rows if (row["true_technique_id"].strip() in {
                (row[f"{method}_top{i}"] or "").strip() for i in range(1, k + 1)
            }))
            counts[f"top{k}"] = {"hits": hits, "n": expected_positions, "accuracy": hits / expected_positions}
        scores[method] = {"label": label, **counts}
    return {
        "input_file": path.name,
        "positions": expected_positions,
        "metric_definition": "A_k = number of rows whose true technique ID appears in the first k ranked candidate IDs / number of held-out rows",
        "scores": scores,
        "note": "This validates consistency between per-position rankings and aggregate metrics. It does not verify that training or the candidate rankings were generated without leakage.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("prediction_csv", type=Path)
    parser.add_argument("--json-out", type=Path, default=Path("prediction_metric_audit.json"))
    args = parser.parse_args()
    try:
        result = validate_and_score(args.prediction_csv)
    except PredictionLogError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result["scores"], indent=2))
    print(f"Wrote {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
