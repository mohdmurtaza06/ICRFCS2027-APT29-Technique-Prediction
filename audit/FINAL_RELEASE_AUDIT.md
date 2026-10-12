# ICRFCS 2027 release audit

> **Completion-pass supersession note (12 October 2026):** This file retains earlier dated audit sections for provenance. The current source of truth is `COMPLETION_AUDIT_2026-10-12.md`, with status in the root `STATUS.txt` and open gates in `docs/SUBMISSION_GATE.md`. The package now contains four controlled conditions and 37 passing tests. Earlier statements in Parts A/B about only two conditions, 31 tests, or conference requirements not being checked are historical snapshots and are superseded by the completion pass.


## Part A - Empirical audit and manuscript update (2026-10-12)

**Verdict:** empirical work executed and independently reconciled; submission not fully cleared (open items in section A7). Part B below is the earlier packaging-stage audit; where it says the benchmark or manuscript was not updated, Part A supersedes it.

### A1. Inventory
The supplied archive contained scripts, tests, a historical manuscript and audit documents. It did **not** contain `data/*.json` or `artifacts_reflecting_walk/` (the earlier run directory). The latter was therefore neither inspected nor modified. Authentic inputs were downloaded here from the pinned sources and bundled.

### A2. Data provenance
- Joystick commit `8bee0d3...`: all five vendor JSON Git blob IDs equal the pinned values; SHA-256 values are in the manifests.
- Reconstruction: 140 positions, 140 unique substeps, 58 distinct technique IDs per file; all five ordered (substep, technique) sequences identical.
- ATT&CK Enterprise v18.1 bundle SHA-256 `f857d8f7...62fb`: 835 technique IDs (691 active, 12 deprecated, 132 revoked).
- Coverage: all 58 observed IDs are in the catalogue (read independently from the STIX JSON by `reconcile_run.py`). 23 of 58 observed labels (13 of 42 target positions) are revoked/deprecated IDs; all observed labels are parent-level.

### A3. Protocol checks
98/42 split confirmed; in all 252 prediction rows (3 seeds x 42 x 2 conditions) the true label equals `sequence[98+j]`, each of the five rankings has five unique candidates inside the catalogue, ties are broken by ascending ID. The source code builds the prefix with `allowed_prefix`, which excludes the current target; LSTM examples come from synthetic sequences plus the first 98 observed positions (92 observed windows). 11 of 42 targets are labels absent from the context (8 are first occurrences overall).

### A4. Tests and recomputation
- 31 tests pass (the 24 historical tests plus boundary-rule and reconciliation tests). In this environment torch was initially absent, so the end-to-end smoke test errored (24 tests, 1 error) until torch 2.14.1 was installed; it then passed.
- `scripts/reconcile_run.py` recomputes every Top-1/3/5 hit from the CSVs without importing the benchmark code. All values equal `metrics_by_seed.json` in both conditions. Its tests include tamper detection (changed metric, out-of-catalogue candidate, changed source hash). Writing the tests exposed a single-seed crash in the script, which was fixed.
- Repeated full runs produced byte-identical predictions and synthetic corpora.

### A5. Principal finding: generator boundary rule
The handover describes a generator that **reflects** at the tactic boundaries, but the script in the archive **clamps** (`min`/`max`). Clamping makes the last tactic nearly absorbing: ~50-51% of synthetic instances are Impact-tagged techniques and 66-70% of sequences end in one, although none of the 140 observed instances is Impact. Re-running with reflection (`--boundary reflect`) reproduces **every** seed-level hit count and mean in the handover (`audit/handover_crosscheck.json`), which strongly indicates that the earlier artifacts used reflection and that the archived script had drifted from the code that produced them. Reflection is therefore the primary condition because it is the documented design and matches the prior record, not because it scores better; the clamped condition is reported as sensitivity. The default was changed to `reflect`; `--boundary clamp` retains the archived behaviour (verified byte-identical to the pre-refactor run). Method ordering differs between conditions (paper Tables II-III), e.g. LSTM top-5 5.6% vs 0%, co-occurrence 6.3% vs 11.9%.

### A6. Results (primary, mean accuracy over three seeds, hits out of 42 per seed)
| Method | Top-1 | Top-3 | Top-5 |
|---|---|---|---|
| Frequency | 0.0% | 0.8% | 1.6% |
| Co-occurrence | 0.8% | 2.4% | 6.3% |
| Markov-1 | 0.8% | 5.6% | 12.7% |
| Markov-2 + backoff | 4.8% | 6.3% | 11.9% |
| LSTM | 0.0% | 1.6% | 5.6% |

Uniform random reference: 0.12%, 0.36%, 0.60%. Descriptive pilot only: one emulation sequence, 42 dependent positions, seeds are not independent, differences between the better methods are within seed spread, generator not validated. Hyperparameters were fixed beforehand and not tuned.

### A7. Not verified / open
- Original `artifacts_reflecting_walk/` not available; only handover-stated counts compared.
- Windows/Python 3.14.7 rerun not performed here.
- Reference metadata was not re-verified in this pass (earlier file flags Erfan et al. volume and Pappu landing page).
- Conference page limit, template, blind-review rules, similarity report and publication arrangements not checked.
- No rollout evaluation, no uncertainty analysis beyond seed spread, no tuning of baselines or LSTM.
- Contradiction recorded: `audit/pre_correction_run_summary.json` (58-label, sequence-derived vocabulary) disagrees with the handover's seed tables; it is retained only as a historical audit trail and is not used anywhere in the paper.

## Part B - Earlier packaging-stage audit (historical)


Date: 2026-10-12  
Scope: supplied `ICRFCS2027_COMPLETE_REBUILD_AND_SUBMISSION_MATERIALS.zip`, source files contained in that archive, subsequent code and terminal outputs supplied in the conversation, and the corrected source package assembled here.

## Verdict

**Source-package hardening completed. Empirical/submission clearance not granted.** The original bundle did not contain the later local `data/*.json` downloads or the later `artifacts/` outputs. The packaging environment also could not reach the raw-data hosts. A genuine corrected benchmark run against the five authentic source JSONs and the downloaded v18.1 catalogue was therefore not possible here. No corrected accuracy figures are invented or substituted.

## Issues found in the earlier clean-room code

1. **Test-set vocabulary contamination:** the prior script created its 58-label vocabulary from all 140 ordered labels before the chronological split. The held-out suffix's identities could affect candidate ranking space.
2. **Baseline information inconsistency:** the earlier frequency baseline was frozen after synthetic data plus the initial context, while Markov and co-occurrence counts were updated from the expanding teacher-forced prefix.
3. **Limited tests:** prior tests covered generator repeatability, stable ties, metric arithmetic, and transition counting. They did not assert held-out target exclusion, catalogue-defined candidate coverage, ranking membership, or LSTM example source restrictions.
4. **Incomplete provenance:** the earlier manifest hashed the five vendor JSON files but did not record the catalogue, benchmark-script hash, runtime versions, or a seed-sensitivity summary.
5. **Historic run outputs not bundled:** the supplied ZIP predates the user’s later run and lacked its `artifacts/` metrics and raw per-position CSVs. A compact, explicitly pre-correction metrics summary is recorded from the user-reported run, but the row-level rankings are unavailable in this release archive.
6. **Manuscript mismatch:** the included LaTeX/PDF is a historical 58-technique draft with unverified historical scores. It is not yet consistent with the corrected open-catalogue implementation and must be revised only after actual corrected predictions are generated.

## Changes made in this release

- Added `scripts/load_attack_catalogue.py`, which loads MITRE ATT&CK Enterprise v18.1 from the `v18.1` tag, validates the bundle’s declared Enterprise collection version, and records the file hash. The loader does not accept the APT29 sequence as input. It retains deprecated/revoked technique objects if they remain in that pinned release so that historic labels may remain rankable; all observed sequence IDs must still be present in the independent catalogue.
- Pinned APT29 inputs to a verified immutable Joystick commit and added Git blob identity validation. Existing local files with mismatching blob IDs cause a fail-closed error unless the caller explicitly requests refresh; the benchmark manifest also records the source commit and local-input SHA-256 hashes.
- Reworked `scripts/run_benchmark.py` so its new default output directory is `artifacts_corrected`, and it refuses to write into a nonempty output directory.
- Added a checked helper that returns the allowed historical prefix and target separately at each step.
- Made all count-based predictors use synthetic counts plus the same currently allowed prefix, including frequency.
- Made LSTM training examples derive from synthetic sequences and the first 98 observed positions only; the held-out suffix is not passed into the training-example builder.
- Added ranking validation for candidate membership, exact top-five length, and duplicate labels.
- Expanded the manifest to include vendor/catalogue/source script hashes, catalogue hash/version, package versions, run configuration, split protocol, tie policy, synthetic statistics and seed-sensitivity metadata.
- Added tests for catalogue parsing, target-prefix exclusion, target coverage, ranking constraints and training-example inputs.
- Rewrote README, status and submission-gate documents to distinguish code-level checks from empirical clearance.

## Verification performed here

- Unit tests: 24 passed, including an offline fixture-based end-to-end smoke test.
- `compileall` on `scripts` and `tests`: passed.
- MITRE source verification: the official ATT&CK STIX repository index lists Enterprise ATT&CK v18.1 as released on 13 November 2025. MITRE's April 2026 v19 update notes that the Enterprise Defense Evasion tactic was split into Stealth and Defense Impairment; v18.1 is used here to preserve the pre-v19 taxonomy expected by the generator.
- Immutable APT29 source check: the five result files were fetched from Joystick commit `8bee0d3128abc08c4e00c60b01c1608e162bb9ce` via GitHub and independently flattened/sorted in the tool session. Each file yielded 140 positions, 140 unique substeps, and 58 technique IDs; all five ordered `(SubStep, TechniqueId)` sequences matched. The source file Git blob SHA-1s and commit details are listed in `audit/pinned_source_revision_audit.json`. This is source consistency verification, not a model benchmark run.
- A fixture-based end-to-end smoke run: passed with synthetic five-label source files and a mocked catalogue. This validates orchestration/output shape only, not actual model results.
- A full corrected benchmark run on the authentic data: **not performed**. Outbound raw GitHub data downloads were unavailable in this packaging environment, and the source archive did not include the later data files.
- Final IEEE LaTeX/PDF: source content remains the historical draft; it was rebuilt to six pages and visually inspected during this audit. It still describes the historical 58-label protocol and is not updated to corrected open-catalogue results.
- Similarity/plagiarism check: not performed.

## What this proves and does not prove

Passing fixture tests proves the tested code branches behave as asserted for those fixtures. It does not establish the corrected scores, catalogue coverage of the actual 140 labels, performance on other campaigns, or the scientific validity of the heuristic synthetic generator. The five vendor results are multiple views of the same emulation, not five independent campaigns. Three random seeds are run sensitivity on the same 42 sequentially dependent target positions, not 126 independent observations.

## Required next steps before empirical submission

1. Run the command in README on an internet-enabled machine with the five source JSONs and v18.1 catalogue.
2. If catalogue coverage fails, stop. Select and document an independent ATT&CK release that contains every historical label; do not add labels by inspecting the held-out sequence.
3. Inspect source hashes and the cross-vendor sequence audit.
4. Reconcile every prediction CSV against the per-seed metrics JSON independently.
5. Inspect synthetic pool coverage, length statistics and all 42 prediction rows for each seed.
6. Update the LaTeX source and PDF to the corrected vocabulary, method, exact results, limitations and manifest. Remove or clearly segregate historical unverified scores.
7. Recompile and visually inspect all PDF pages, verify all references, double-blind anonymity, conference formatting, and required similarity report.

## Source links

- MITRE ATT&CK STIX data index: https://github.com/mitre-attack/attack-stix-data/blob/master/index.md
- Pinned v18.1 Enterprise data: https://github.com/mitre-attack/attack-stix-data/blob/v18.1/enterprise-attack/enterprise-attack-18.1.json
- MITRE v19 updates: https://attack.mitre.org/resources/updates/updates-april-2026/
- APT29 evaluation source JSONs pinned to commit `8bee0d3128abc08c4e00c60b01c1608e162bb9ce`: https://github.com/mitre-attack/joystick/tree/8bee0d3128abc08c4e00c60b01c1608e162bb9ce/data/evaluations/apt29
