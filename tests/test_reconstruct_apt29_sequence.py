import json
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from reconstruct_apt29_sequence import reconstruct, audit, ReconstructionError, git_blob_sha1, SOURCE_COMMIT, EXPECTED_GIT_BLOB_SHA1


def payload(step_rows):
    # step_rows: [(substep, technique_id, technique_name)]
    techs = []
    for substep, technique_id, name in step_rows:
        techs.append({
            "TechniqueId": technique_id,
            "TechniqueName": name,
            "Tactics": [{"TacticName": "Execution"}],
            "Steps": [{"SubStep": substep}],
        })
    return {"Techniques": techs}


class TestReconstruction(unittest.TestCase):
    def test_source_revision_is_pinned_and_git_blob_hash_is_correct(self):
        import hashlib
        sample = b"hello\n"
        expected = hashlib.sha1(b"blob 6\0" + sample).hexdigest()
        self.assertEqual(git_blob_sha1(sample), expected)
        self.assertEqual(SOURCE_COMMIT, "8bee0d3128abc08c4e00c60b01c1608e162bb9ce")
        self.assertEqual(set(EXPECTED_GIT_BLOB_SHA1), {
            "McAfee.1.APT29.1_Results.json", "Microsoft.1.APT29.1_Results.json",
            "FireEye.1.APT29.1_Results.json", "CrowdStrike.1.APT29.1_Results.json",
            "Bitdefender.1.APT29.1_Results.json",
        })

    def write_json(self, base, name, data):
        p = base / name
        p.write_text(json.dumps(data), encoding="utf-8")
        return p

    def test_numeric_order_not_lexical(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "data.json"
            p.write_text(json.dumps(payload([
                ("11.A.1", "T3", "Eleven"),
                ("2.A.2", "T2", "Two-B"),
                ("2.A.1", "T1", "Two-A"),
            ])), encoding="utf-8")
            seq = reconstruct(p)
            self.assertEqual([r["substep"] for r in seq], ["2.A.1", "2.A.2", "11.A.1"])

    def test_duplicate_substeps_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "data.json"
            p.write_text(json.dumps(payload([
                ("1.A.1", "T1", "A"),
                ("1.A.1", "T2", "B"),
            ])), encoding="utf-8")
            with self.assertRaises(ReconstructionError):
                reconstruct(p)

    def test_vendor_pair_identity(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            a = self.write_json(base, "a.json", payload([("1.A.1", "T1", "A"), ("2.A.1", "T2", "B")]))
            b = self.write_json(base, "b.json", payload([("2.A.1", "T2", "B"), ("1.A.1", "T1", "A")]))
            result = audit([a, b])
            self.assertTrue(result["cross_vendor_pairwise_identity_to_reference"])

    def test_vendor_mismatch_detected(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            a = self.write_json(base, "a.json", payload([("1.A.1", "T1", "A")]))
            b = self.write_json(base, "b.json", payload([("1.A.1", "T9", "Different")]))
            result = audit([a, b])
            self.assertFalse(result["cross_vendor_pairwise_identity_to_reference"])
            self.assertTrue(result["source_files"][1]["first_differences_vs_reference"])


if __name__ == "__main__":
    unittest.main()
