# Final submission gate

**Current verdict: NOT FULLY CLEARED.** The in-package empirical and software checks pass, and the candidate manuscript meets the visible page-count/anonymization checks. External compliance checks still require action. Do not describe this package as formally accepted, similarity-cleared, or submission-ready until the open gates below are resolved.

## Empirical integrity and reproducibility
- [x] Candidate vocabulary is derived from independent, pinned ATT&CK Enterprise v18.1 catalogue (835 technique IDs), not the evaluation sequence.
- [x] All 58 observed technique labels are covered; the run fails closed rather than adding test-derived labels.
- [x] Cross-vendor reconstruction checked: five vendor files yield the same ordered 140-position emulation sequence. These are not five independent campaigns.
- [x] Chronological 98-position initial context and 42-position teacher-forced target suffix checked.
- [x] Leakage/prefix and ranking tests pass; every output row is reconciled to its allowed target position.
- [x] Four full generator conditions are present, run under a shared recorded runtime/script hash set, seeds 20261011/12/13, 500 synthetic sequences per seed, lengths 20-140, 35 LSTM epochs, six-step window, one CPU intra-op thread.
- [x] Condition list: `artifacts_primary_reflect/`, `artifacts_sensitivity_clamp/`, `artifacts_sensitivity_uniform_tactic/`, `artifacts_sensitivity_active_only/`.
- [x] All four `reconciliation.json` files state `all_checks_passed: true`; `audit/sensitivity_comparison.json` reports `status: PASS` and records matching runtime, source and script hashes, seeds, and protocol dimensions.
- [x] 37 tests pass: `python -m unittest discover -s tests -q`. `python -m compileall -q scripts tests` passes.
- [x] Synthetic sensitivity is described as a heuristic stress test; no condition is declared more realistic or selected to maximize accuracy.
- [x] Historical 58-label scores are segregated as unverified/not reproduced, not blended with the 835-candidate results.
- [ ] Original user-local `artifacts_reflecting_walk/` directory is absent from the uploaded source archive. The current reflect run matches preserved handover hit counts, but the original raw outputs could not be inspected directly.
- [ ] Windows rerun in the author's reported Python 3.14.7 / PyTorch 2.14.1 environment remains outstanding; cross-platform bit identity is not established.

## Manuscript and conference checks
- [x] Manuscript reflects the corrected independent 835-ID candidate universe and uses corrected-run results for the primary benchmark.
- [x] All four generator policies and their limits are described; the local co-occurrence baseline is not mislabeled as hierarchical clustering.
- [x] Three seeds are described as sensitivity on the same 42 dependent positions, not as independent campaigns.
- [x] IEEEtran compilation succeeds; the current candidate PDF is 5 pages on US Letter, within the screenshot-stated 4-6 pages including references.
- [x] Rendered all five pages and visually checked for clipping, blank pages and layout failures.
- [x] PDF Author metadata is blank; source uses `Anonymous Submission`; no identifying strings for the submitting author were found in the manuscript-text scan.
- [x] Conference submission screenshot archived in `audit/conference_submission_screenshot_2026-10-12.png`; readable requirements transcribed in `audit/conference_submission_requirements_2026-10-12.md`.
- [x] Official site checked for dates, scope, publication statement and registration conditions. IEEE Xplore inclusion is not guaranteed by the conference's own wording.
- [ ] Similarity report not obtained. The stated 15% ceiling is **not verified**.
- [ ] Reference [10] (Pappu) remains partially verified. Title, author, conference and DOI match an author-uploaded full text, but an authoritative IEEE proceedings record was not retrieved; the manuscript omits the unverified page range.
- [ ] Full source-level checking of every cited claim was not performed; metadata verification is not a guarantee that every citation supports its associated claim.
- [ ] No manuscript submission has been sent; acceptance and publication are not implied.

## Before sending the paper
1. Obtain a similarity report from an accepted service; inspect any matches and revise honestly without using similarity evasion.
2. Seek authoritative IEEE proceedings metadata for Pappu [10]; until then, retain the manuscript's citation without the unverified page range or replace the reference with a fully verified source.
3. Run the documented suite on Windows if cross-platform validation is required, saving exact environment and reconciliation outputs.
4. Review the paper's contribution and scope critically; the current experiment is a small pilot and may be judged too narrow or too synthetic for acceptance.
5. Reconfirm all conference submission details and the correct submission email before sending.
