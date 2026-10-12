import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

class SummarizeConditionTests(unittest.TestCase):
    def _run(self, root: Path, label: str, hit: int, source_hash: str = "same"):
        d = root / label
        d.mkdir()
        manifest = {
            "test_positions": 42,
            "context_positions": 98,
            "python_and_package_versions": {"python": "3.13.5", "torch": "2.10.0"},
            "source_hashes": [{"file": "input.json", "sha256": source_hash}],
            "configuration": {"seeds": [1], "lstm_epochs": 1, "lstm_window_size": 6, "synthetic_sequences_per_seed": 1},
        }
        metrics = {"1": {}}
        for method in ("frequency", "cooccurrence", "markov1", "markov2_backoff", "lstm"):
            for k in (1, 3, 5):
                metrics["1"][f"{method}_top{k}"] = {"hits": hit, "n": 42, "accuracy": hit/42}
        (d / "run_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        (d / "metrics_by_seed.json").write_text(json.dumps(metrics), encoding="utf-8")
        (d / "reconciliation.json").write_text(json.dumps({"all_checks_passed": True}), encoding="utf-8")
        return d

    def test_summarizes_reconciled_compatible_runs(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            a = self._run(root, "a", 2)
            b = self._run(root, "b", 4)
            cmd = [sys.executable, str(ROOT / "scripts" / "summarize_conditions.py"),
                   "--condition", f"a={a}", "--condition", f"b={b}"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('"status": "PASS"', result.stdout)
            self.assertIn('"mean_accuracy_pct": 4.761904761904762', result.stdout)

    def test_rejects_mismatched_sources(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            a = self._run(root, "a", 2, "one")
            b = self._run(root, "b", 4, "two")
            cmd = [sys.executable, str(ROOT / "scripts" / "summarize_conditions.py"),
                   "--condition", f"a={a}", "--condition", f"b={b}"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn("not directly comparable", result.stderr)

if __name__ == "__main__":
    unittest.main()
