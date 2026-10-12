import csv, hashlib, io, json, sys, tempfile, unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import reconcile_run

METHODS = ["frequency", "cooccurrence", "markov1", "markov2_backoff", "lstm"]


def build_run(root: Path):
    ids = [f"T{1000 + i}" for i in range(100)]
    bundle = {"objects": [{"type": "attack-pattern", "external_references": [
        {"source_name": "mitre-attack", "external_id": t}]} for t in ids]}
    data, run = root / "data", root / "run"
    data.mkdir(); run.mkdir()
    cat = data / "enterprise-attack-18.1.json"
    cat.write_text(json.dumps(bundle))
    seq = [ids[i % 10] for i in range(140)]
    (run / "apt29_sequence.json").write_text(json.dumps([{"technique_id": t} for t in seq]))
    manifest = {"source_hashes": [{"file": cat.name, "sha256": hashlib.sha256(cat.read_bytes()).hexdigest()}],
                "candidate_vocabulary_size": 100}
    (run / "run_manifest.json").write_text(json.dumps(manifest))
    metrics = {}
    rows = []
    for j in range(42):
        true = seq[98 + j]
        row = {"position": j + 1, "sequence_index": 99 + j, "true_technique_id": true}
        for m in METHODS:
            row[m + "_top5"] = json.dumps([true] + [t for t in ids if t != true][:4]) if m == "markov1" else json.dumps(ids[50:55])
        rows.append(row)
    with (run / "predictions_seed_1.csv").open("w", newline="") as h:
        w = csv.DictWriter(h, fieldnames=list(rows[0]))
        w.writeheader(); w.writerows(rows)
    metrics["1"] = {f"{m}_top{k}": {"hits": 42 if m == "markov1" else 0, "n": 42} for m in METHODS for k in (1, 3, 5)}
    (run / "metrics_by_seed.json").write_text(json.dumps(metrics))
    return run, data


def run_main(run, data):
    with mock.patch.object(sys, "argv", ["x", "--run-dir", str(run), "--data-dir", str(data)]), redirect_stdout(io.StringIO()):
        return reconcile_run.main()


class ReconcileTests(unittest.TestCase):
    def test_consistent_run_passes(self):
        with tempfile.TemporaryDirectory() as d:
            run, data = build_run(Path(d))
            self.assertEqual(run_main(run, data), 0)

    def test_tampered_metric_is_detected(self):
        with tempfile.TemporaryDirectory() as d:
            run, data = build_run(Path(d))
            p = run / "metrics_by_seed.json"
            m = json.loads(p.read_text()); m["1"]["markov1_top5"]["hits"] = 41
            p.write_text(json.dumps(m))
            self.assertEqual(run_main(run, data), 1)

    def test_candidate_outside_catalogue_is_detected(self):
        with tempfile.TemporaryDirectory() as d:
            run, data = build_run(Path(d))
            p = run / "predictions_seed_1.csv"
            p.write_text(p.read_text().replace("T1050", "T9999", 1))
            self.assertEqual(run_main(run, data), 1)

    def test_changed_source_file_is_detected(self):
        with tempfile.TemporaryDirectory() as d:
            run, data = build_run(Path(d))
            cat = data / "enterprise-attack-18.1.json"
            cat.write_text(cat.read_text() + " ")
            self.assertEqual(run_main(run, data), 1)


if __name__ == "__main__":
    unittest.main()
