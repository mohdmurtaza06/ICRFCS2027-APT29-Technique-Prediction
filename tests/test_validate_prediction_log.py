import csv
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from validate_prediction_log import METHODS, required_columns, validate_and_score, PredictionLogError


class TestPredictionLogValidation(unittest.TestCase):
    def make_log(self, path, duplicate=False):
        columns = required_columns()
        with path.open("w", newline="", encoding="utf-8") as h:
            writer = csv.DictWriter(h, fieldnames=columns)
            writer.writeheader()
            for pos in range(1, 43):
                row = {"position": pos, "true_technique_id": f"T{pos}"}
                for method in METHODS:
                    ranked = [f"T{pos}", f"X{pos}a", f"X{pos}b", f"X{pos}c", f"X{pos}d"]
                    if duplicate and pos == 1 and method == "global_frequency":
                        ranked[1] = ranked[0]
                    for i, candidate in enumerate(ranked, start=1):
                        row[f"{method}_top{i}"] = candidate
                writer.writerow(row)

    def test_recompute_scores(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "predictions.csv"
            self.make_log(p)
            result = validate_and_score(p)
            self.assertEqual(result["scores"]["global_frequency"]["top1"]["hits"], 42)
            self.assertEqual(result["scores"]["lstm_mixed"]["top5"]["accuracy"], 1.0)

    def test_duplicate_ranked_candidates_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "predictions.csv"
            self.make_log(p, duplicate=True)
            with self.assertRaises(PredictionLogError):
                validate_and_score(p)


if __name__ == "__main__":
    unittest.main()
