# GOV-02 PILOT-01 — independent Red Team handoff

**Author handoff:** `GOV_02_PILOT_01_PASS_READY_FOR_INDEPENDENT_REDTEAM`. Not self-accepted by an independent reviewer or product owner.

**Execution commit:** `429e08f182c7d01e2a158968cf963817b09cb0f1`, [run 41482929656 attempt 1](https://github.com/ErenTahiroglu/Security-Assurance-Runner/actions/runs/41482929656), Linux job `125405680860` success. **Cleanup commit:** `74702276cee637c61ec08c7c75fa49ab46166d2a` removed the one-shot workflow and authorization marker. Full provenance, observed safeguards, failure histories and restricted evidence digests: [execution report](GOV_02_PILOT_01_EXECUTION_REPORT.md) and [test matrix](GOV_02_PILOT_01_TEST_MATRIX.md).

Review source at final source SHA `c16d9facb01607e6ae33185569140b6f9fd70d8c`, execution SHA and cleanup SHA. Inspect `scripts/gov02/pilot01/{preflight.sh,verify_spec.py,probe.c,scan_once.sh,inspect_report.py,test_inspect_report.py,test_verify_spec.py}`, and historical one-shot workflow at execution SHA. The current `development` no longer contains that executable workflow/marker.

Challenge the exact SHA source pin, archive/extracted binary checks, tar handling, container config, positive/negative network test limitations, child cleanup, error/exit mapping, controlled corpus and rule, native JSON report parsing, path/secret privacy, strict worktree/mount exclusions and whether a rearm/replay can bypass the one-shot chain. Confirm no raw report content in normal CI logs, no external scanner egress, and no real user repository scan. No uncontrolled fuzz, hostile exploit, third-party scanner or production tests were run.

Reproduction commands for non-scanner tests: `cargo fmt --all -- --check`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked`, `cargo build --locked`, `python3 -m unittest discover -s scripts/gov02/pilot01 -p 'test_*.py'`, `bash -n scripts/gov02/pilot01/preflight.sh`, `bash -n scripts/gov02/pilot01/scan_once.sh`. Run actual scanner again **only under separately granted new authorization**, never by merely rerunning the historical workflow.

**Limits:** pass means controlled synthetic Gitleaks pilot, not independent authentication of native reports, production coverage or operational PASS. Issue #4 remains OPEN for the broader GOV-02 roadmap, and `main` remains frozen.
