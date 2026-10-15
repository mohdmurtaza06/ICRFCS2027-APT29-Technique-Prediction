# ICRFCS 2027 TTP forecasting: audited clean-room pilot benchmark

**Package status (15 October 2026):** the four controlled benchmark conditions reconcile, 37 tests pass, and a separate full Windows rebuild is evidenced in the user's archived package (`Full rebuild: True`, `Result: PASS`; all four conditions compared successfully). The public repository's historical status files had not yet been synchronized with that later evidence. The Windows evidence is not bundled in this repository revision, and cross-platform bit identity is not claimed. Submission is **not yet cleared** because the checker shown in the similarity screenshot has not been confirmed as accepted by the conference. See `STATUS.txt` and `docs/SUBMISSION_GATE.md`.

## Research task

This is a pilot next-technique Top-k ranking benchmark on one 140-position sequence reconstructed from public MITRE ATT&CK Evaluations APT29 material. Five vendor result files reconstruct to the same sequence, not five independent campaigns. The initial context contains 98 positions; the remaining 42 positions are evaluated sequentially with teacher-forced prefixes. Candidate IDs come from the independent, pinned ATT&CK Enterprise v18.1 catalogue (835 technique IDs). No target-derived label is added to the candidate vocabulary.

Methods are global frequency, local co-occurrence association ranking (not hierarchical clustering), first-order Markov, second-order Markov with backoff, and LSTM. Count-based models use synthetic counts plus the currently permitted observed prefix. LSTM training uses synthetic windows plus the initial 98 observed positions only.

## Four comparable benchmark conditions

All four included conditions use the same source/script hashes, runtime, seeds, 500 synthetic sequences per seed, 20-140 length range, 35 epochs, six-step LSTM window, and 98/42 split. Each has per-position predictions, generated corpora, a manifest and an independent reconciliation report.

| Directory | Generator policy | Purpose |
|---|---|---|
| `artifacts_primary_reflect/` | Ordered tactic walk with reflecting boundaries; all catalogue statuses in synthetic pool | Primary documented policy |
| `artifacts_sensitivity_clamp/` | Ordered tactic walk with clamped boundaries; all catalogue statuses retained | Boundary-rule sensitivity |
| `artifacts_sensitivity_uniform_tactic/` | Independently select tactic uniformly at each position; all catalogue statuses retained | Tactic transition sensitivity |
| `artifacts_sensitivity_active_only/` | Reflecting walk; only active techniques sampled for synthetic training | Catalogue-status sensitivity |

The evaluation candidate vocabulary remains all 835 IDs for every condition. `audit/sensitivity_comparison.json` contains the strict comparability result, per-seed hits, mean accuracies, seed dispersion, hashes and runtime.

## Primary result and interpretation

In the primary reflecting condition, mean Top-5 accuracy across three seeds is 12.7% for Markov-1, 11.9% for Markov-2 with backoff, 6.3% for co-occurrence, 5.6% for LSTM, and 1.6% for frequency. The tested generator policies change some model rankings considerably. These are descriptive results on the same 42 dependent positions from one emulation, not 126 independent examples and not evidence of generalizable or operational APT prediction. The random-walk synthetic generator is a heuristic and has not been validated as a realistic attack simulator.

An earlier 58-label experiment's numbers remain in the paper only in an explicitly labelled historical/unverified table. Its original row-level artifacts were unavailable and those figures are not comparable with the corrected open-catalogue task.

## Reproduce

Install `requirements.txt`, then run:

```bash
python -m compileall -q scripts tests
python -m unittest discover -s tests -v
python scripts/run_benchmark.py --outdir repro_primary_reflect --data-dir data --seeds 20261011 20261012 20261013 --epochs 35 --n-synthetic 500 --boundary reflect --tactic-sampling walk --synthetic-status all --torch-threads 1
python scripts/reconcile_run.py --run-dir repro_primary_reflect --data-dir data
```

Each output directory must be new and empty. Repeat with different new output names and the respective flags for other conditions:

```bash
# Clamping boundary sensitivity
python scripts/run_benchmark.py --outdir repro_sensitivity_clamp --data-dir data --seeds 20261011 20261012 20261013 --epochs 35 --n-synthetic 500 --boundary clamp --tactic-sampling walk --synthetic-status all --torch-threads 1
# Uniform tactic-selection sensitivity
python scripts/run_benchmark.py --outdir repro_sensitivity_uniform_tactic --data-dir data --seeds 20261011 20261012 20261013 --epochs 35 --n-synthetic 500 --boundary reflect --tactic-sampling uniform --synthetic-status all --torch-threads 1
# Active-only synthetic techniques sensitivity
python scripts/run_benchmark.py --outdir repro_sensitivity_active_only --data-dir data --seeds 20261011 20261012 20261013 --epochs 35 --n-synthetic 500 --boundary reflect --tactic-sampling walk --synthetic-status active --torch-threads 1
```

After all four output directories are complete and reconciled, compare them with:

```bash
python scripts/summarize_conditions.py --condition primary=repro_primary_reflect --condition clamp=repro_sensitivity_clamp --condition uniform_tactic=repro_sensitivity_uniform_tactic --condition active_only=repro_sensitivity_active_only --out audit/sensitivity_comparison_repro.json
```

The four bundled conditions were measured under Python 3.13.5, NumPy 2.3.5, PyTorch 2.10.0+cpu, pandas 2.2.3, and scikit-learn 1.8.0, using one CPU intra-op thread. `requirements.txt` intentionally records the author-reported Windows dependency pins, not the container versions used for the supplied outputs. For any fresh comparison, run all four policies in the same environment; `summarize_conditions.py` rejects mismatched environments. The user's archived Windows acceptance evidence records a full rebuild of all four conditions and `sensitivity_comparison_windows.json` with `status: PASS` under Windows 10, Python 3.13.15, NumPy 2.5.4, and PyTorch 2.14.1. The environment capture reports pandas and scikit-learn as not installed; the recorded benchmark/reconciliation nevertheless completed. This Windows evidence is in the user's archived package, not this public repository snapshot. Do not expect bit-identical LSTM outputs across OS/library versions.

## Conference requirements and open gates

The 12 October screenshot from `https://icrfcs.com/submission.html` states: IEEE conference template; 4-6 pages including figures/tables/references; double-blind review; no names, affiliations or acknowledgments in initial submissions; maximum 15% similarity; and electronic email submission to `teamicrfcs@gmail.com`. The candidate manuscript compiles to five pages and its PDF Author field is blank, but no similarity report was obtained. Pappu reference [10] remains partially verified because authoritative IEEE proceedings metadata was not retrieved; the manuscript omits the unverified page range. The original Windows rerun is outstanding. See `docs/SUBMISSION_GATE.md` before submission.

A screenshot of a Duplichecker run supplied on 15 October 2026 reports 97% unique, 3% exact matches, 0% partial matches, and 10+ sources. This is preliminary evidence only: the conference has not yet confirmed that Duplichecker is an accepted checker, and source matches still need manual review. Do not describe the paper as similarity-cleared until the conference confirms the checker or an explicitly accepted service produces a report. The conference's dates and publication statement do not guarantee acceptance or IEEE Xplore inclusion. No submission has been sent.
