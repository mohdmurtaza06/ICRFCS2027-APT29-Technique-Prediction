# Package contents (completion pass, 2026-10-12)

This archive contains source, pinned inputs, four controlled benchmark conditions, a five-page anonymized IEEEtran manuscript and audit evidence. **It is an audited pilot package, not similarity-cleared or formally submission-ready.** See `STATUS.txt`, `audit/COMPLETION_AUDIT_2026-10-12.md`, and `docs/SUBMISSION_GATE.md`.

- `scripts/`: independent catalogue loader, source reconstruction, benchmark with explicit generator policies, metric reconciler, multi-condition comparability auditor, prediction-log validator.
- `tests/`: 37 automated tests covering source reconstruction, catalogue handling, protocol/prefix constraints, rankings, policy behavior, metrics and comparability.
- `data/`: pinned MITRE ATT&CK Enterprise v18.1 STIX file and five APT29 vendor source JSON files. Hashes and provenance are documented.
- `artifacts_primary_reflect/`: canonical primary run under controlled runtime; reflecting tactic walk, all catalogue statuses available for synthetic training.
- `artifacts_sensitivity_clamp/`: boundary sensitivity run under the same runtime.
- `artifacts_sensitivity_uniform_tactic/`: uniform tactic sampling sensitivity run under the same runtime.
- `artifacts_sensitivity_active_only/`: active-only synthetic technique pool sensitivity run; evaluation vocabulary remains all 835 IDs.
- Every condition contains per-position rankings, metrics by seed, synthetic corpora, run manifest, source/cross-vendor records, and independent `reconciliation.json`.
- `audit/sensitivity_comparison.json`: strict comparability and descriptive summary across all four conditions.
- `ICRFCS2027_TTP_Paper_Source.tex` and `.pdf`: current manuscript source and compiled five-page anonymous PDF.
- `historical/`: superseded 58-label manuscript for provenance only; its numbers are labelled unverified/not reproduced.
- `audit/`: completion report, environment notes, official conference requirement notes/screenshot, reference status, reproducibility records, and SHA-256 inventory.
- `docs/SUBMISSION_GATE.md`: evidence-based submission checklist with remaining external blockers.

Excluded: Python virtual environments, caches, LaTeX intermediates and render PNGs used during inspection, transient console captures, credentials, and duplicate run directories from earlier runtimes.
