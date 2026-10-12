import unittest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from run_benchmark import (
    METHODS, allowed_prefix, build_lstm_examples, stable_rank,
    validate_rankings, validate_target_coverage,
)


class EvaluationProtocolTests(unittest.TestCase):
    def test_target_is_not_in_its_own_prefix(self):
        observed = [f"T{i:04d}" for i in range(140)]
        prefix, target = allowed_prefix(observed, 98, 0)
        self.assertEqual(len(prefix), 98)
        self.assertEqual(prefix, observed[:98])
        self.assertEqual(target, observed[98])
        self.assertNotIn(target, prefix)

    def test_each_step_uses_only_prior_positions(self):
        observed = [f"T{i:04d}" for i in range(140)]
        for offset in range(42):
            prefix, target = allowed_prefix(observed, 98, offset)
            self.assertEqual(len(prefix), 98 + offset)
            self.assertEqual(target, observed[98 + offset])
            self.assertNotIn(target, prefix)

    def test_out_of_range_target_fails_closed(self):
        with self.assertRaises(ValueError):
            allowed_prefix(["A", "B"], 1, 1)

    def test_vocab_coverage_rejects_unknown_target_without_augmenting_vocab(self):
        vocab = ["T1", "T2", "T3", "T4", "T5"]
        with self.assertRaises(ValueError):
            validate_target_coverage(["T1", "T2", "OUTSIDE"], vocab)
        self.assertNotIn("OUTSIDE", vocab)

    def test_rankings_are_unique_and_inside_candidate_universe(self):
        vocab = ["T1", "T2", "T3", "T4", "T5", "T6"]
        row = {"true_technique_id": "T6"}
        for method in METHODS:
            row[method + "_top5"] = stable_rank({"T6": 10, "T2": 9}, vocab, 5)
        validate_rankings([row], vocab)
        row["lstm_top5"] = ["T1", "T1", "T2", "T3", "T4"]
        with self.assertRaises(ValueError):
            validate_rankings([row], vocab)

    def test_lstm_examples_do_not_consume_heldout_suffix(self):
        # Function accepts only the synthetic sequences and permitted context; the
        # held-out suffix is intentionally not an argument to the training builder.
        vocab = ["T1", "T2", "T3"]
        index = {token: i for i, token in enumerate(vocab)}
        synthetic = [["T1", "T2", "T3", "T1", "T2", "T3", "T1"]]
        context = ["T3", "T2", "T1", "T3", "T2", "T1", "T3"]
        examples = build_lstm_examples(synthetic, context, index, win=6)
        self.assertEqual(len(examples), 2)
        self.assertEqual(examples[0][1], index["T1"])
        self.assertEqual(examples[1][1], index["T3"])


if __name__ == "__main__":
    unittest.main()
