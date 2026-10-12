# Completion audit: ICRFCS 2027 TTP prediction pilot

**Audit date:** 12 October 2026  
**Disposition:** Empirical/package checks passed for four controlled conditions. Submission clearance remains open because there is no similarity report, one reference is partially verified, and a Windows reproduction has not been run.

## 1. Scope and evidence

The working candidate was built from the uploaded `ICRFCS2027_FINAL_VERIFIED.zip`. That original upload is unchanged. The release working tree contains the pinned source JSONs, benchmark scripts, test suite, primary and sensitivity artifacts, the current IEEEtran source/PDF, and audit files. The locally reported `artifacts_reflecting_walk/` directory was not in the uploaded ZIP, so it could not be directly inspected.

The official conference submission requirements were read from the screenshot provided by the author and are archived at `audit/conference_submission_screenshot_2026-10-12.png`. The screenshot states use of the conference template, 4-6 pages including references/figures/tables, double-blind review, no author names/affiliations/acknowledgments in the initial submission, a 15% similarity ceiling, and email submission via `teamicrfcs@gmail.com`. Relevant official conference pages were also checked for dates, scope, publication wording and registration conditions; see `audit/conference_submission_requirements_2026-10-12.md`.

## 2. Test and code status

Executed in the container runtime recorded in `audit/executed_environment_2026-10-12.txt`:

- `python -m compileall -q scripts tests`: passed.
- `python -m unittest discover -s tests -q`: **37 tests passed**.
- Four full benchmark conditions executed with the same runtime and source/script hash set. The policies differ only in the documented generator knobs: reflecting vs clamped boundary; reflecting walk vs independently uniform tactic selection; all catalogue statuses vs active-only synthetic technique availability.
- `scripts/reconcile_run.py` independently recalculated hit counts from the output CSVs. Every condition's `reconciliation.json` has `all_checks_passed: true`.
- `scripts/summarize_conditions.py` confirmed matching seed list, target/context dimensions, candidate-universe size, input hashes, script hashes, package versions and shared model settings. `audit/sensitivity_comparison.json` status is `PASS`.

The existing original archive was not altered. For a consistent final evidence set, the two canonical directories `artifacts_primary_reflect/` and `artifacts_sensitivity_clamp/` now hold the common-runtime reruns. The duplicate earlier-runtime directories have been removed from the completion copy. Both additional sensitivity conditions are included.

## 3. Data provenance and protocol

- APT29 structured results are pinned to Joystick commit `8bee0d3128abc08c4e00c60b01c1608e162bb9ce`.
- All five vendor files reconstruct to the same ordered sequence of 140 `(SubStep, TechniqueId)` positions, with 140 unique substeps and 58 distinct technique IDs. These are repeated vendor views of one emulation, not independent campaigns.
- ATT&CK Enterprise v18.1 STIX bundle SHA-256: `f857d8f78f2f0c0b7db321a711a39fba98546c1e3076a657684850c83d0962fb`.
- Candidate set: 835 technique IDs. All 58 observed labels are covered; no evaluation labels are appended to the candidate vocabulary.
- Protocol: first 98 observed positions as initial context, remaining 42 targets evaluated sequentially with allowed teacher-forced prefix.
- Three seeds per condition (20261011, 20261012, 20261013), 500 synthetic sequences per seed, length 20-140, 35 LSTM epochs, six-step input window, CPU intra-op threads set to 1.

## 4. Results and interpretation

The primary reflecting condition's mean Top-1/Top-3/Top-5 accuracies across the three runs are:

| Method | Top-1 | Top-3 | Top-5 |
|---|---:|---:|---:|
| Frequency | 0.0% | 0.8% | 1.6% |
| Co-occurrence | 0.8% | 2.4% | 6.3% |
| Markov-1 | 0.8% | 5.6% | 12.7% |
| Markov-2 + backoff | 4.8% | 6.3% | 11.9% |
| LSTM | 0.0% | 1.6% | 5.6% |

All four-condition values and seed-level hits are in `audit/sensitivity_comparison.json`. In the uniform-tactic condition, Top-5 means are frequency 0.8%, co-occurrence 10.3%, Markov-1 11.1%, Markov-2/backoff 11.9%, and LSTM 0.8%. In the active-only synthetic condition, respective Top-5 means are 0.8%, 3.2%, 10.3%, 11.9%, and 4.0%.

These are descriptive results on the same 42 sequentially dependent positions. The three seeds quantify synthetic-run sensitivity, not 126 independent targets. Model rankings depend on the generator policy; the synthetic random walk is not a validated attack simulator. These results do not establish cross-campaign or operational adversary prediction capability.

The historical 58-label scores remain clearly labelled as unverified and not reproduced. They cannot be compared directly to the corrected 835-candidate task because vocabulary, protocol and original per-position artifacts differ or are missing.

## 5. Manuscript and PDF

- Source: `ICRFCS2027_TTP_Paper_Source.tex`.
- Build: PDFLaTeX/latexmk completed without fatal errors; log at `audit/final_latex_compile.log`.
- PDF: five pages, US Letter, within the 4-6 page limit in the provided conference screenshot.
- Render: all five pages were rendered and visually inspected; no clipped table/text, blank page or layout failure was observed.
- `pdfinfo` Author field is blank and source says `Anonymous Submission`.
- The manuscript text was searched for likely author name, college, university and email identifiers; no matches were found. This is a practical scan, not a formal guarantee against every possible identity leak.
- The paper correctly identifies the co-occurrence method as local association ranking, presents the sensitivity tests, separates historical unverified scores, and explains the dependent single-sequence evaluation.

## 6. Remaining non-code / external gates

1. **Similarity:** No similarity report is supplied or obtained. The stated maximum 15% remains unverified. Do not imply compliance without a valid report.
2. **Reference [10]:** Pappu's title, author, conference and DOI match an author-uploaded public copy. The manuscript now omits the unverified proceedings page range 761-764 rather than presenting it as fact. The reference remains partially verified until authoritative IEEE proceedings metadata is retrieved.
3. **Windows reproduction:** Not run in the author-reported Windows Python 3.14.7 / PyTorch 2.14.1 environment. Cross-platform bit identity is not claimed.
4. **Original local run artifacts:** `artifacts_reflecting_walk/` was not included in the uploaded ZIP. Primary-condition metrics match the seed-level counts preserved in the handover, but the original row-level outputs could not be directly compared.
5. **Scientific scope:** The study is a pilot based on one emulation sequence, 42 dependent targets, a synthetic heuristic and untuned baselines. Broader claims would require multiple independent ordered campaigns, better-supported generation assumptions, and a free-running evaluation.
6. **Submission:** No submission has been emailed; acceptance or IEEE Xplore inclusion is not implied.

## 7. Release decision

**Release disposition: audited research/package candidate, NOT submission-cleared.** In-scope code, data provenance, metric reconciliation, controlled sensitivity experiments, manuscript compilation and visual PDF inspection are complete. The residual gates require external evidence or a Windows environment and should be closed before submission.
