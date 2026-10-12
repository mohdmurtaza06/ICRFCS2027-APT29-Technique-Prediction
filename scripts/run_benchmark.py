#!/usr/bin/env python3
"""Corrected clean-room benchmark; not a reproduction of the lost experiment.

Evaluation: chronological 98-step initial context, followed by 42 teacher-forced
next-step predictions from one MITRE ATT&CK Evaluations APT29 emulation flow.
Candidate vocabulary and tactic mappings are loaded from an independent, pinned
ATT&CK Enterprise catalogue, not derived from all 140 evaluation labels.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
from datetime import datetime, timezone
import importlib.metadata
import json
import platform
import random
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable, Sequence

import numpy as np

TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]
METHODS = ["frequency", "cooccurrence", "markov1", "markov2_backoff", "lstm"]
CONTEXT_SIZE = 98
EXPECTED_SEQUENCE_LENGTH = 140
WINDOW_SIZE = 6


def stable_rank(scores: dict, vocab: Sequence[str], k: int = 5) -> list[str]:
    """Rank a de-duplicated candidate universe by descending score, then ID."""
    candidates = sorted(set(vocab))
    if k < 1:
        raise ValueError("k must be >= 1")
    return sorted(candidates, key=lambda t: (-float(scores.get(t, 0.0)), t))[:k]


def apply_boundary(pos: int, n_states: int, mode: str) -> int:
    """Keep a tactic index inside [0, n_states-1].

    "reflect" (default) mirrors out-of-range moves back into range; this is the documented
    benchmark design and reproduces the earlier artifacts_reflecting_walk hit counts exactly.
    "clamp" saturates at the first/last tactic, which makes the last tactic absorbing-like; it is
    the behaviour of the script as originally shipped in the rebuild archive and is kept only as a
    labelled sensitivity condition.
    """
    if mode == "clamp":
        return min(max(pos, 0), n_states - 1)
    if mode == "reflect":
        if n_states == 1:
            return 0
        while pos < 0 or pos >= n_states:
            pos = -pos if pos < 0 else 2 * (n_states - 1) - pos
        return pos
    raise ValueError(f"Unknown boundary mode: {mode}")


def generate_synthetic(
    vocab: Sequence[str], tactic_map: dict[str, set[str]], n_sequences: int = 500,
    min_len: int = 20, max_len: int = 140, seed: int = 20261011, boundary: str = "reflect",
    tactic_sampling: str = "walk", allowed_techniques: set[str] | None = None,
) -> list[list[str]]:
    """Generate heuristic synthetic sequences, not realistic campaigns.

    tactic_sampling="walk" uses the ordered tactic walk; "uniform" samples a
    tactic uniformly and independently at every position. allowed_techniques
    filters only synthetic choices; it never alters the evaluation vocabulary.
    """
    if n_sequences < 1 or min_len < 1 or max_len < min_len:
        raise ValueError("Require n_sequences >= 1 and 1 <= min_len <= max_len")
    if boundary not in ("clamp", "reflect"):
        raise ValueError(f"Unknown boundary mode: {boundary}")
    if tactic_sampling not in ("walk", "uniform"):
        raise ValueError(f"Unknown tactic sampling policy: {tactic_sampling}")
    rng = random.Random(seed)
    allowed = set(vocab) if allowed_techniques is None else set(allowed_techniques)
    pools = {
        t: [v for v in vocab if v in allowed and t in tactic_map.get(v, set())]
        for t in TACTIC_ORDER
    }
    pools = {t: p for t, p in pools.items() if p}
    order = [t for t in TACTIC_ORDER if t in pools]
    if not order:
        raise ValueError("No allowed technique pools overlap the configured tactic order")

    out: list[list[str]] = []
    for _ in range(n_sequences):
        n = rng.randint(min_len, max_len)
        pos = 0
        seq: list[str] = []
        for j in range(n):
            if tactic_sampling == "uniform":
                # Prespecified sensitivity: choose a tactic uniformly at each position.
                pos = rng.randrange(len(order))
            elif j:
                u = rng.random()
                if u < 0.55:
                    pos = apply_boundary(pos + 1, len(order), boundary)
                elif u < 0.80:
                    pass
                elif u < 0.93:
                    pos = apply_boundary(pos - rng.choice([1, 2]), len(order), boundary)
                else:
                    pos = apply_boundary(pos + rng.choice([2, 3]), len(order), boundary)
            seq.append(rng.choice(pools[order[pos]]))
        out.append(seq)
    return out


def load_technique_status(path: Path) -> dict[str, str]:
    """Return catalogue-only status labels for ATT&CK technique objects."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    status_map: dict[str, str] = {}
    for obj in payload.get("objects", []):
        if not isinstance(obj, dict) or obj.get("type") != "attack-pattern":
            continue
        for ref in obj.get("external_references", []):
            if (
                isinstance(ref, dict)
                and ref.get("source_name") == "mitre-attack"
                and isinstance(ref.get("external_id"), str)
                and ref["external_id"].startswith("T")
            ):
                tid = ref["external_id"]
                status_map[tid] = (
                    "revoked" if obj.get("revoked")
                    else "deprecated" if obj.get("x_mitre_deprecated")
                    else "active"
                )
                break
    if not status_map:
        raise ValueError(f"No ATT&CK technique status values found in {path}")
    return status_map


def count_models(sequences: Iterable[Sequence[str]]):
    uni = Counter()
    first = defaultdict(Counter)
    second = defaultdict(Counter)
    cooc = defaultdict(Counter)
    for seq in sequences:
        uni.update(seq)
        for a, b in zip(seq, seq[1:]):
            first[a][b] += 1
        for a, b, c in zip(seq, seq[1:], seq[2:]):
            second[(a, b)][c] += 1
        for i, a in enumerate(seq):
            for j in range(max(0, i - 5), min(len(seq), i + 6)):
                if i != j:
                    cooc[a][seq[j]] += 1
    return uni, first, second, cooc


def merge(dst, src):
    for key, value in src.items():
        dst[key].update(value)
    return dst


def compute_metrics(rows: list[dict], methods: Sequence[str] = METHODS) -> dict:
    out = {}
    n = len(rows)
    for method in methods:
        for k in (1, 3, 5):
            hits = sum(r["true_technique_id"] in r[method + "_top5"][:k] for r in rows)
            out[f"{method}_top{k}"] = {"hits": hits, "n": n, "accuracy": hits / n if n else None}
    return out


def allowed_prefix(observed: Sequence[str], context_size: int, target_offset: int):
    """Return only the history available immediately before this target and its label."""
    target_index = context_size + target_offset
    if context_size < 1 or target_offset < 0 or target_index >= len(observed):
        raise ValueError("Prediction position is outside the held-out suffix")
    prefix = list(observed[:target_index])
    target = observed[target_index]
    if len(prefix) != target_index:
        raise AssertionError("Unexpected prefix length")
    return prefix, target


def validate_target_coverage(observed: Sequence[str], vocab: Sequence[str]) -> None:
    missing = sorted(set(observed) - set(vocab))
    if missing:
        raise ValueError(
            "Pinned candidate catalogue cannot represent every evaluation label. "
            "Refusing to silently add target-derived IDs or score impossible rankings. "
            f"Missing IDs: {missing}"
        )


def validate_rankings(rows: Sequence[dict], vocab: Sequence[str], methods: Sequence[str] = METHODS) -> None:
    candidates = set(vocab)
    for i, row in enumerate(rows, start=1):
        if row.get("true_technique_id") not in candidates:
            raise ValueError(f"Row {i}: true target is not in candidate universe")
        for method in methods:
            key = method + "_top5"
            ranking = row.get(key)
            if not isinstance(ranking, list) or len(ranking) != min(5, len(candidates)):
                raise ValueError(f"Row {i}: {key} must contain exactly min(5, vocab size) candidates")
            if len(ranking) != len(set(ranking)):
                raise ValueError(f"Row {i}: duplicate candidates in {key}")
            if not set(ranking).issubset(candidates):
                raise ValueError(f"Row {i}: {key} includes a candidate outside the vocabulary")


def build_lstm_examples(sequences: Sequence[Sequence[str]], context: Sequence[str], token_to_ix: dict[str, int], win: int = WINDOW_SIZE):
    """Build training pairs from synthetic sequences and allowed context only."""
    examples = []
    for seq in list(sequences) + [list(context)]:
        ids = [token_to_ix[token] for token in seq]
        examples.extend((ids[i - win:i], ids[i]) for i in range(win, len(ids)))
    return examples


def package_versions() -> dict[str, str]:
    names = {"numpy": "numpy", "torch": "torch", "pandas": "pandas", "scikit-learn": "scikit-learn"}
    out = {"python": platform.python_version()}
    for label, distribution in names.items():
        try:
            out[label] = importlib.metadata.version(distribution)
        except importlib.metadata.PackageNotFoundError:
            out[label] = "not-installed"
    return out


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def summarize_seed_metrics(all_metrics: dict[str, dict]) -> dict:
    """Summarize run-seed sensitivity; seed runs are not independent sequences."""
    summary = {}
    metric_keys = sorted({key for metrics in all_metrics.values() for key in metrics})
    for key in metric_keys:
        values = {seed: metrics[key]["accuracy"] for seed, metrics in all_metrics.items()}
        numeric = [float(value) for value in values.values() if value is not None]
        summary[key] = {
            "mean_accuracy_across_seeds": statistics.mean(numeric) if numeric else None,
            "sample_sd_across_seeds": statistics.stdev(numeric) if len(numeric) > 1 else 0.0 if numeric else None,
            "hits_by_seed": {seed: all_metrics[seed][key]["hits"] for seed in all_metrics},
            "accuracy_by_seed": values,
            "n_positions_per_seed": {seed: all_metrics[seed][key]["n"] for seed in all_metrics},
            "interpretation": "seed sensitivity on the same 42 dependent positions, not independent campaign-level uncertainty",
        }
    return summary


def get_vendor_files(data_dir: Path, refresh: bool = False) -> list[Path]:
    from reconstruct_apt29_sequence import VENDOR_FILES, EXPECTED_GIT_BLOB_SHA1, download_vendor_files, git_blob_sha1
    local = [data_dir / name for name in VENDOR_FILES]
    if all(path.is_file() and path.stat().st_size > 0 for path in local) and not refresh:
        mismatches = []
        for path in local:
            actual = git_blob_sha1(path.read_bytes())
            expected = EXPECTED_GIT_BLOB_SHA1[path.name]
            if actual != expected:
                mismatches.append(f"{path.name}: expected {expected}, got {actual}")
        if mismatches:
            raise ValueError(
                "Local vendor files do not match the pinned Joystick revision. "
                "Move them aside or use --refresh-vendor-data to replace them with the pinned files. "
                + "; ".join(mismatches)
            )
        return local
    return download_vendor_files(data_dir)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--outdir", default="artifacts_corrected", help="New output directory; does not overwrite prior artifacts")
    parser.add_argument("--data-dir", default="data")
    parser.add_argument("--seeds", type=int, nargs="*", default=[20261011, 20261012, 20261013])
    parser.add_argument("--epochs", type=int, default=35)
    parser.add_argument("--n-synthetic", type=int, default=500)
    parser.add_argument("--boundary", choices=["clamp", "reflect"], default="reflect",
                        help="Tactic-walk boundary rule. reflect = documented primary design; clamp = shipped-archive variant (sensitivity)")
    parser.add_argument("--tactic-sampling", choices=["walk", "uniform"], default="walk",
                        help="Synthetic tactic sampling: ordered random walk or independent uniform tactic selection")
    parser.add_argument("--synthetic-status", choices=["all", "active"], default="all",
                        help="Synthetic technique eligibility only; the catalogue-wide evaluation vocabulary is unchanged")
    parser.add_argument("--torch-threads", type=int, default=1,
                        help="CPU intra-op thread count for reproducible, low-overhead execution (default: 1)")
    parser.add_argument("--refresh-vendor-data", action="store_true", help="Redownload vendor JSONs even if local copies exist")
    args = parser.parse_args()

    if not args.seeds or len(set(args.seeds)) != len(args.seeds):
        parser.error("Provide at least one unique seed")
    if args.epochs < 1 or args.n_synthetic < 1 or args.torch_threads < 1:
        parser.error("--epochs, --n-synthetic, and --torch-threads must be positive")

    out = Path(args.outdir)
    data = Path(args.data_dir)
    catalogue_path = data / "enterprise-attack-18.1.json"
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        parser.error(f"Output directory {out} is not empty; choose a new directory to preserve prior results")

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from reconstruct_apt29_sequence import audit, DEFAULT_REPOSITORY, SOURCE_COMMIT
    from load_attack_catalogue import load_catalogue

    try:
        files = get_vendor_files(data, refresh=args.refresh_vendor_data)
        audit_obj = audit(files)
        if not audit_obj["cross_vendor_pairwise_identity_to_reference"]:
            raise ValueError("Cross-vendor sequence mismatch.")
        seq = audit_obj["sequence"]
        observed = [record["technique_id"] for record in seq]
        if len(observed) != EXPECTED_SEQUENCE_LENGTH:
            raise ValueError(f"Expected {EXPECTED_SEQUENCE_LENGTH} positions, got {len(observed)}")
        vocab, tactic_map, catalogue_metadata = load_catalogue(catalogue_path)
        status_map = load_technique_status(catalogue_path)
        validate_target_coverage(observed, vocab)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    (out / "apt29_sequence.json").write_text(json.dumps(seq, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (out / "cross_vendor_audit.json").write_text(
        json.dumps({key: value for key, value in audit_obj.items() if key != "sequence"}, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (out / "catalogue_metadata.json").write_text(json.dumps(catalogue_metadata, indent=2) + "\n", encoding="utf-8")

    import torch
    from torch import nn
    torch.set_num_threads(args.torch_threads)

    context, target = observed[:CONTEXT_SIZE], observed[CONTEXT_SIZE:]
    if len(target) != EXPECTED_SEQUENCE_LENGTH - CONTEXT_SIZE:
        raise AssertionError("Split does not yield 42 target positions")

    all_metrics: dict[str, dict] = {}
    manifests = []
    for seed in args.seeds:
        random.seed(seed)
        np.random.seed(seed)
        torch.manual_seed(seed)
        torch.use_deterministic_algorithms(True, warn_only=False)

        allowed_techniques = {tid for tid, status in status_map.items() if status == "active"} if args.synthetic_status == "active" else set(vocab)
        synthetic = generate_synthetic(
            vocab, tactic_map, args.n_synthetic, seed=seed, boundary=args.boundary,
            tactic_sampling=args.tactic_sampling, allowed_techniques=allowed_techniques,
        )
        synthetic_lengths = [len(sequence) for sequence in synthetic]
        (out / f"synthetic_seed_{seed}.json").write_text(
            json.dumps({
                "seed": seed,
                "n_sequences": len(synthetic),
                "min_length": min(synthetic_lengths),
                "max_length": max(synthetic_lengths),
                "mean_length": statistics.mean(synthetic_lengths),
                "total_instances": sum(synthetic_lengths),
                "sequences": synthetic,
            }, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

        syn_uni, syn_first, syn_second, syn_cooc = count_models(synthetic)
        token_to_ix = {technique: index for index, technique in enumerate(vocab)}
        examples = build_lstm_examples(synthetic, context, token_to_ix, WINDOW_SIZE)
        X = torch.tensor([x for x, _ in examples], dtype=torch.long)
        Y = torch.tensor([y for _, y in examples], dtype=torch.long)

        class Net(nn.Module):
            def __init__(self, n: int):
                super().__init__()
                self.emb = nn.Embedding(n, 32)
                self.lstm = nn.LSTM(32, 64, batch_first=True)
                self.drop = nn.Dropout(0.2)
                self.fc = nn.Linear(64, n)

            def forward(self, x):
                z, _ = self.lstm(self.emb(x))
                return self.fc(self.drop(z[:, -1, :]))

        model = Net(len(vocab))
        optimizer = torch.optim.Adam(model.parameters(), lr=0.003)
        loss_fn = nn.CrossEntropyLoss()
        generator = torch.Generator().manual_seed(seed)
        for _epoch in range(args.epochs):
            model.train()
            for batch in torch.randperm(len(X), generator=generator).split(256):
                optimizer.zero_grad()
                loss = loss_fn(model(X[batch]), Y[batch])
                loss.backward()
                optimizer.step()
        model.eval()

        rows = []
        for j in range(len(target)):
            prefix, true = allowed_prefix(observed, CONTEXT_SIZE, j)
            _, prefix_first, prefix_second, prefix_cooc = count_models([prefix])
            # Every count-based method receives synthetic training counts plus the same
            # allowed observed prefix, including the newly revealed teacher-forced history.
            frequency_counts = Counter(syn_uni)
            frequency_counts.update(prefix)
            first = merge(defaultdict(Counter), syn_first)
            merge(first, prefix_first)
            second = merge(defaultdict(Counter), syn_second)
            merge(second, prefix_second)
            cooc = merge(defaultdict(Counter), syn_cooc)
            merge(cooc, prefix_cooc)

            frequency = stable_rank(frequency_counts, vocab)
            markov1 = stable_rank(first[prefix[-1]], vocab)
            last_pair = tuple(prefix[-2:])
            markov2_scores = second[last_pair] if second[last_pair] else first[prefix[-1]]
            markov2 = stable_rank(markov2_scores, vocab)
            association_scores = Counter()
            for technique in prefix[-WINDOW_SIZE:]:
                association_scores.update(cooc[technique])
            association = stable_rank(association_scores, vocab)
            input_ids = torch.tensor([[token_to_ix[technique] for technique in prefix[-WINDOW_SIZE:]]], dtype=torch.long)
            with torch.no_grad():
                logits = model(input_ids)[0].cpu().numpy()
            lstm_scores = {technique: float(logits[index]) for index, technique in enumerate(vocab)}
            lstm = stable_rank(lstm_scores, vocab)

            rows.append({
                "position": j + 1,
                "sequence_index": CONTEXT_SIZE + j + 1,
                "true_technique_id": true,
                "frequency_top5": frequency,
                "cooccurrence_top5": association,
                "markov1_top5": markov1,
                "markov2_backoff_top5": markov2,
                "lstm_top5": lstm,
            })

        validate_rankings(rows, vocab)
        metrics = compute_metrics(rows, METHODS)
        all_metrics[str(seed)] = metrics
        prediction_path = out / f"predictions_seed_{seed}.csv"
        with prediction_path.open("w", newline="", encoding="utf-8") as handle:
            fields = ["position", "sequence_index", "true_technique_id"] + [method + "_top5" for method in METHODS]
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            for row in rows:
                writer.writerow({key: json.dumps(row[key]) if isinstance(row[key], list) else row[key] for key in fields})

        instance_counts = Counter(token for sequence in synthetic for token in sequence)
        instance_status_counts = Counter(status_map.get(token, "unknown") for token in instance_counts.elements())
        technique_tactic_membership_counts = Counter(
            tactic for token, count in instance_counts.items() for tactic in tactic_map.get(token, set()) for _ in range(count)
        )
        manifests.append({
            "seed": seed,
            "synthetic_sequences": len(synthetic),
            "synthetic_total_instances": sum(synthetic_lengths),
            "synthetic_min_length": min(synthetic_lengths),
            "synthetic_max_length": max(synthetic_lengths),
            "synthetic_mean_length": statistics.mean(synthetic_lengths),
            "training_examples": len(examples),
            "lstm_epochs": args.epochs,
            "context_size": len(context),
            "test_positions": len(target),
            "synthetic_instance_status_counts": dict(sorted(instance_status_counts.items())),
            "synthetic_unique_techniques_sampled": len(instance_counts),
            "synthetic_top_10_technique_instances": [
                {"technique_id": tid, "count": count, "fraction": count / sum(instance_counts.values())}
                for tid, count in instance_counts.most_common(10)
            ],
            "synthetic_tactic_membership_counts_nonexclusive": dict(sorted(technique_tactic_membership_counts.items())),
            "metrics": metrics,
        })

    (out / "metrics_by_seed.json").write_text(json.dumps(all_metrics, indent=2) + "\n", encoding="utf-8")
    (out / "metrics_seed_sensitivity.json").write_text(json.dumps(summarize_seed_metrics(all_metrics), indent=2) + "\n", encoding="utf-8")
    source_hashes = [{"file": path.name, "sha256": sha256_file(path)} for path in files]
    source_hashes.append({"file": catalogue_path.name, "sha256": sha256_file(catalogue_path)})
    manifest = {
        "status": "new_corrected_clean_room_experiment",
        "not_reproduction_of_lost_original": True,
        "date_utc": datetime.now(timezone.utc).isoformat(),
        "python_and_package_versions": package_versions(),
        "script_hashes": {
            "run_benchmark.py": sha256_file(Path(__file__).resolve()),
            "load_attack_catalogue.py": sha256_file(Path(__file__).with_name("load_attack_catalogue.py")),
            "reconstruct_apt29_sequence.py": sha256_file(Path(__file__).with_name("reconstruct_apt29_sequence.py")),
        },
        "configuration": {
            "seeds": args.seeds,
            "synthetic_sequences_per_seed": args.n_synthetic,
            "synthetic_length_bounds": [20, 140],
            "lstm_epochs": args.epochs,
            "torch_cpu_intraop_threads": torch.get_num_threads(),
            "lstm_window_size": WINDOW_SIZE,
            "context_positions": CONTEXT_SIZE,
            "test_positions": len(target),
            "tactic_walk_order": TACTIC_ORDER,
            "tactic_walk_boundary": args.boundary if args.tactic_sampling == "walk" else "not_applicable_for_independent_uniform_tactic_sampling",
            "tactic_sampling_policy": args.tactic_sampling,
            "synthetic_technique_status_policy": "active_only" if args.synthetic_status == "active" else "all_catalogue_statuses_retained",
        },
        "source_hashes": source_hashes,
        "vendor_source": {
            "repository_revision_url": DEFAULT_REPOSITORY,
            "commit": SOURCE_COMMIT,
        },
        "catalogue": catalogue_metadata,
        "sequence_length": len(seq),
        "distinct_technique_ids_observed": len(set(observed)),
        "candidate_vocabulary_size": len(vocab),
        "observed_label_coverage": "100% required; run aborts if an observed label is absent from the pinned catalogue",
        "context_positions": CONTEXT_SIZE,
        "test_positions": len(target),
        "evaluation": "teacher-forced next-step; at each position only the initial 98 positions and earlier held-out observations are inputs",
        "count_baseline_protocol": "synthetic counts plus current permitted prefix for all count-based baselines, including frequency",
        "lstm_training_protocol": "synthetic sequences plus first 98 observed positions; no held-out suffix examples added to training; inference conditions on the allowed rolling prefix window",
        "synthetic_generator": (
            "heuristic ordered tactic walk through ATT&CK Enterprise tactics; not validated as realistic attack simulator"
            if args.tactic_sampling == "walk"
            else "independent uniform selection over non-empty ATT&CK tactic pools; not validated as realistic attack simulator"
        ),
        "random_walk_probabilities": {"advance_one": 0.55, "stay": 0.25, "back_one_or_two": 0.13, "advance_two_or_three": 0.07} if args.tactic_sampling == "walk" else None,
        "synthetic_status_policy_note": "Status filtering affects synthetic generation only; the ranking candidate universe remains all retained IDs from the pinned independent catalogue.",
        "ranking_rule": "descending score, then ascending technique ID for deterministic ties; candidate set de-duplicated",
        "cooccurrence_note": "association ranking from +/-5-position counts; not hierarchical clustering",
        "statistical_note": "seed summary describes sensitivity on the same 42 dependent positions; seeds do not create independent campaigns",
        "runs": manifests,
    }
    (out / "run_manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"metrics_by_seed": all_metrics, "metrics_seed_sensitivity": summarize_seed_metrics(all_metrics), "manifest": manifest}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
