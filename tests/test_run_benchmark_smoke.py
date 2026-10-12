"""Offline integration smoke test using tiny synthetic source fixtures, not real MITRE data."""
import json
import sys
import tempfile
import unittest
import io
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import run_benchmark


class BenchmarkSmokeTests(unittest.TestCase):
    def test_end_to_end_output_shape_with_fixtures(self):
        from reconstruct_apt29_sequence import VENDOR_FILES
        vocab = ["T1001", "T1002", "T1003", "T1004", "T1005"]
        tactic_map = {token: {"Execution"} for token in vocab}
        observed_ids = [vocab[i % len(vocab)] for i in range(140)]
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            data = root / "data"
            data.mkdir()
            output = root / "out"
            for filename in VENDOR_FILES:
                techniques = []
                for idx, technique_id in enumerate(observed_ids, start=1):
                    techniques.append({
                        "TechniqueId": technique_id,
                        "TechniqueName": f"Fixture technique {technique_id}",
                        "Tactics": [{"TacticName": "Execution"}],
                        "Steps": [{"SubStep": str(idx)}],
                    })
                (data / filename).write_text(json.dumps({"Techniques": techniques}), encoding="utf-8")
            catalogue_path = data / "enterprise-attack-18.1.json"
            catalogue_path.write_text(json.dumps({"objects": [
                {"type": "attack-pattern", "external_references": [
                    {"source_name": "mitre-attack", "external_id": token}
                ]}
                for token in vocab
            ]}), encoding="utf-8")
            fake_meta = {"catalogue": "fixture", "version": "test", "sha256": "fixture"}
            fake_args = [
                "run_benchmark.py", "--outdir", str(output), "--data-dir", str(data),
                "--seeds", "101", "--epochs", "1", "--n-synthetic", "8",
            ]
            with patch.object(sys, "argv", fake_args), patch.object(
                sys.modules.get("load_attack_catalogue") or __import__("load_attack_catalogue"),
                "load_catalogue", return_value=(vocab, tactic_map, fake_meta),
            ), patch.object(run_benchmark, "get_vendor_files", return_value=[data / name for name in VENDOR_FILES]):
                with redirect_stdout(io.StringIO()):
                    exit_code = run_benchmark.main()

            self.assertEqual(exit_code, 0)
            metrics = json.loads((output / "metrics_by_seed.json").read_text(encoding="utf-8"))
            predictions = (output / "predictions_seed_101.csv").read_text(encoding="utf-8").splitlines()
            manifest = json.loads((output / "run_manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(metrics["101"]["lstm_top5"]["n"], 42)
            self.assertEqual(len(predictions), 43)  # header + 42 positions
            self.assertEqual(manifest["context_positions"], 98)
            self.assertEqual(manifest["test_positions"], 42)
            self.assertEqual(manifest["candidate_vocabulary_size"], 5)
            self.assertTrue((output / "catalogue_metadata.json").is_file())


    def test_local_vendor_files_must_match_pinned_revision(self):
        from reconstruct_apt29_sequence import VENDOR_FILES
        with tempfile.TemporaryDirectory() as td:
            data = Path(td)
            for name in VENDOR_FILES:
                (data / name).write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "do not match the pinned Joystick revision"):
                run_benchmark.get_vendor_files(data)



if __name__ == "__main__":
    unittest.main()
