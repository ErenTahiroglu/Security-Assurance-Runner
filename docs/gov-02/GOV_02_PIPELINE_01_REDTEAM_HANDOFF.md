# GOV-02 PIPELINE-01 — Independent Red Team handoff

**Author classification: `GOV_02_PIPELINE_01_READY_FOR_INDEPENDENT_REDTEAM`.** This is not an independent approval, real Gitleaks scan, production attestation, or release. Review code commit `2cb1ecf746d93040f4349910ba162c583bebbc0a` and its exact-SHA CI receipts; a later documentation-only commit must not be substituted for the code-execution SHA.

## Git and evidence

- Partial author baseline: `c80fef0d73b76f43e81fdd98ec59f43a8a799873`; starting accepted EXEC-01 baseline `75d9f1941ce84e99bf2c8369022e562c76fef96c`.
- Code/test implementation in `src/inert_pipeline.rs`, `scripts/gov02/pipeline01/helper.c`, `tests/pipeline_inert_linux.rs`, `src/execution_witness.rs`, `src/lib.rs`, `.github/workflows/gov02-pilot-01-preflight.yml`, plus documents. No `main` changes, no Gitleaks acquisition or execution workflow/marker.
- [Exact-SHA Rust CI 42302288263 attempt 1](https://github.com/ErenTahiroglu/Security-Assurance-Runner/actions/runs/42302288263): 49/49 Rust tests on each Linux x64, Windows x64, macOS ARM64; fmt, Clippy and build successful.
- [Linux scanner-disabled preflight 42302288210 attempt 1](https://github.com/ErenTahiroglu/Security-Assurance-Runner/actions/runs/42302288210): 17 Python tests, actual Docker network positive/negative and cleanup probes, plus the **ignored Linux-only inert Docker integration test explicitly executed** (`cargo test --locked --test pipeline_inert_linux -- --ignored --test-threads=1`), 1 test passed in 9.26s. No scanner executed.
- Existing local unstaged research-PDF `.gitignore` change is outside all GitHub commits. Remote review cannot attest local unstaged tree state; author reports it preserved.

## Review focus

1. Verify `InertCoordinator::run` checks signed test plan and witness **before helper launch**, with out-of-band test keys and fixed digest pin. Check compiled **inert helper** executable digest, fixed TOML-free config bytes and artificial report template; never mistake them for Gitleaks version/provenance.
2. Inspect the exact Docker create arguments and independently read `HostConfig`: `--network none`, read-only root, nonroot 65532, dropped caps, no-new-privileges, 128 MiB memory/swap, 0.5 CPU, 32 PIDs, 3 controlled mounts, immutable fixed entrypoint and mode argument. Review the helper's `/proc` uid/capability check, input/root write rejection and fixed config validation. Docker isolation checks are bounded, not a proof against kernel escape.
3. Trace actual `docker start -a`, timeout, observed `State.ExitCode=23`, `Running=false`, `OOMKilled=false`, no Docker runtime error, and capped/private synthetic report read. Validate output symlink refusal, exact bytes, container/image cleanup and no arbitrary report paths or raw secret-bearing text logged.
4. Check the `#[ignore]` Linux-only Rust integration test is **actually executed** by GitHub Ubuntu preflight rather than silently skipped; verify ordinary Rust CI compiles/tests cross-platform. Adversarial cases include replay before second start, invalid signature and binary identity, invalid source scope, fail exit, partial and oversize report, timeout, cancellation and no container left after failure.
5. Check that `TestReceiptConsumer` prevents duplicate consumption **only within one process instance**. No persistent replay protection exists. The test-helper process observation is true for that local Docker test, but `process_execution_independently_established` in the signed-witness receipt remains false and overall `Decision::Indeterminate` stays unchanged.
6. Confirm the helper is a fixed invented program (not Gitleaks), only inert synthetic report data are produced, the preflight workflow contains no scanner download or scan execution step, and historical real-scanner workflow and marker remain absent.

## Review classification

Use `GOV_02_PIPELINE_01_INDEPENDENT_PASS` only if the above scoped inert-helper evidence and security boundaries genuinely hold; use `GOV_02_PIPELINE_01_CHANGES_REQUESTED` for in-scope defects, or `BLOCKED` only for a demonstrated missing mandatory facility. Do not request production key enrollment, Windows/macOS Docker execution, real Gitleaks rerun, durable database-backed replay or real-depot scanning as a prerequisite for this bounded Linux test milestone.

If accepted, the **next separately owner-authorized work** is an end-to-end real Gitleaks v8.30.1 synthetic-only runner integration with authenticated approved source/config and process-observation semantics; no further real scanner execution is currently authorized. Keep Issue #4 and roadmap #11 open, `main` frozen.
