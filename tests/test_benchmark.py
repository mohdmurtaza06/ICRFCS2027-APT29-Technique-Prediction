import sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from run_benchmark import generate_synthetic, stable_rank, count_models, compute_metrics

class BenchmarkTests(unittest.TestCase):
    def test_stable_tie_break(self):
        self.assertEqual(stable_rank({"T2":1,"T1":1},["T2","T1"],2),["T1","T2"])
    def test_generator_reproducible(self):
        vocab=["T1","T2","T3"]
        tactics={"T1":{"Execution"},"T2":{"Persistence"},"T3":{"Discovery"}}
        a=generate_synthetic(vocab,tactics,5,20,20,42)
        b=generate_synthetic(vocab,tactics,5,20,20,42)
        self.assertEqual(a,b)
        self.assertTrue(all(len(s)==20 for s in a))
    def test_metrics_recomputed(self):
        rows=[{"true_technique_id":"A","m_top5":["A","B","C","D","E"]},
              {"true_technique_id":"Z","m_top5":["A","B","C","D","E"]}]
        result=compute_metrics(rows,["m"])
        self.assertEqual(result["m_top1"]["hits"],1)
        self.assertEqual(result["m_top3"]["hits"],1)
        self.assertEqual(result["m_top5"]["accuracy"],0.5)
    def test_transition_counts(self):
        _, first, second, _ = count_models([["A","B","A"]])
        self.assertEqual(first["A"]["B"],1)
        self.assertEqual(second[("A","B")]["A"],1)
    def test_bad_generator_parameters_fail(self):
        with self.assertRaises(ValueError):
            generate_synthetic(["T1"], {"T1":{"Execution"}}, n_sequences=0)

if __name__=="__main__": unittest.main()


class BoundaryRuleTests(unittest.TestCase):
    def test_clamp_saturates_and_reflect_is_default(self):
        from run_benchmark import apply_boundary
        self.assertEqual(apply_boundary(14, 14, "clamp"), 13)
        self.assertEqual(apply_boundary(-2, 14, "clamp"), 0)
        self.assertEqual(apply_boundary(5, 14, "clamp"), 5)
        vocab = [f"T{i}" for i in range(3)]
        tactics = {"T0": {"Execution"}, "T1": {"Persistence"}, "T2": {"Impact"}}
        self.assertEqual(generate_synthetic(vocab, tactics, 3, 20, 20, 7),
                         generate_synthetic(vocab, tactics, 3, 20, 20, 7, boundary="reflect"))
        self.assertNotEqual(generate_synthetic(vocab, tactics, 20, 140, 140, 7, boundary="clamp"),
                            generate_synthetic(vocab, tactics, 20, 140, 140, 7, boundary="reflect"))

    def test_reflect_mirrors_and_stays_in_range(self):
        from run_benchmark import apply_boundary
        self.assertEqual(apply_boundary(14, 14, "reflect"), 12)
        self.assertEqual(apply_boundary(15, 14, "reflect"), 11)
        self.assertEqual(apply_boundary(-1, 14, "reflect"), 1)
        self.assertEqual(apply_boundary(-2, 14, "reflect"), 2)
        for p in range(-30, 45):
            self.assertTrue(0 <= apply_boundary(p, 14, "reflect") < 14)

    def test_unknown_boundary_rejected(self):
        from run_benchmark import apply_boundary
        with self.assertRaises(ValueError):
            apply_boundary(0, 5, "wrap")
        with self.assertRaises(ValueError):
            generate_synthetic(["T1"], {"T1": {"Execution"}}, 1, 20, 20, 1, boundary="wrap")

class GeneratorPolicyTests(unittest.TestCase):
    def test_uniform_tactic_sampling_is_reproducible(self):
        vocab = ["T1", "T2", "T3"]
        tactics = {"T1": {"Execution"}, "T2": {"Persistence"}, "T3": {"Discovery"}}
        a = generate_synthetic(vocab, tactics, 5, 20, 20, 42, tactic_sampling="uniform")
        b = generate_synthetic(vocab, tactics, 5, 20, 20, 42, tactic_sampling="uniform")
        self.assertEqual(a, b)
        self.assertTrue(all(len(seq) == 20 for seq in a))

    def test_allowed_techniques_filter_only_synthetic_choices(self):
        vocab = ["T1", "T2", "T3"]
        tactics = {"T1": {"Execution"}, "T2": {"Execution"}, "T3": {"Persistence"}}
        generated = generate_synthetic(
            vocab, tactics, 10, 20, 20, 7, allowed_techniques={"T2", "T3"}
        )
        self.assertTrue(all(token in {"T2", "T3"} for seq in generated for token in seq))
        # A disallowed technique may stay in the ranking vocabulary upstream; this helper filters only generation.
        self.assertIn("T1", vocab)

    def test_empty_filtered_pools_fail_closed(self):
        with self.assertRaises(ValueError):
            generate_synthetic(
                ["T1"], {"T1": {"Execution"}}, 1, 20, 20, 1,
                allowed_techniques={"NOT-IN-VOCAB"},
            )

    def test_unknown_tactic_sampling_policy_rejected(self):
        with self.assertRaises(ValueError):
            generate_synthetic(
                ["T1"], {"T1": {"Execution"}}, 1, 20, 20, 1,
                tactic_sampling="weighted-ish",
            )
