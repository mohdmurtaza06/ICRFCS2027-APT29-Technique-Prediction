import json
import tempfile
import unittest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from pathlib import Path

from load_attack_catalogue import load_catalogue


class AttackCatalogueTests(unittest.TestCase):
    def test_active_deprecated_and_revoked_ids_are_from_catalogue_only(self):
        # The fixture is independent of any evaluation sequence. Retaining deprecated
        # or revoked IDs is deliberate to support historic labels if still in v18.1.
        payload = {"objects": [
            {"type": "x-mitre-collection", "name": "Enterprise ATT&CK", "x_mitre_version": "18.1"},
            {"type": "attack-pattern", "external_references": [{"source_name": "mitre-attack", "external_id": "T1001"}],
             "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "command-and-control"}]},
            {"type": "attack-pattern", "x_mitre_deprecated": True,
             "external_references": [{"source_name": "mitre-attack", "external_id": "T1002"}],
             "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}]},
            {"type": "attack-pattern", "revoked": True,
             "external_references": [{"source_name": "mitre-attack", "external_id": "T1003"}],
             "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "persistence"}]},
            {"type": "malware", "external_references": [{"source_name": "mitre-attack", "external_id": "S0001"}]},
        ]}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalogue.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            vocab, tactic_map, metadata = load_catalogue(path, download_if_missing=False)
        self.assertEqual(vocab, ["T1001", "T1002", "T1003"])
        self.assertEqual(tactic_map["T1001"], {"Command and Control"})
        self.assertEqual(tactic_map["T1002"], {"Execution"})
        self.assertEqual(metadata["technique_ids_in_candidate_universe"], 3)
        self.assertEqual(len(metadata["sha256"]), 64)

    def test_empty_catalogue_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "empty.json"
            path.write_text(json.dumps({"objects": [
                {"type": "x-mitre-collection", "name": "Enterprise ATT&CK", "x_mitre_version": "18.1"}
            ]}), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_catalogue(path, download_if_missing=False)

    def test_wrong_release_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "wrong-release.json"
            path.write_text(json.dumps({"objects": [
                {"type": "x-mitre-collection", "name": "Enterprise ATT&CK", "x_mitre_version": "19.2"}
            ]}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Expected MITRE ATT&CK Enterprise v18.1"):
                load_catalogue(path, download_if_missing=False)

    def test_wrong_json_shape_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_text('{"not_objects": []}', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_catalogue(path, download_if_missing=False)


if __name__ == "__main__":
    unittest.main()
