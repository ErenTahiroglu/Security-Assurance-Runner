# GOV-02 PIPELINE-01 — P2 exit-binding and cleanup corrections

**Author classification:** `GOV_02_PIPELINE_01_P2_CORRECTIONS_READY_FOR_INDEPENDENT_REVIEW`; NOT independent acceptance or production readiness.

**Code SHA:** `2b38ea8e0bc71eaaf3df9a5ec48df25d51de17ac`. Base `11a6c90c01057c5be94dbfb2088b9dc1edae5bc9`. Frozen `main`: `956ae354e0e02e05154acc71a0158f5bf96f02fa`.

The author-associated adversarial assessment identified two P2 issues and explicitly declined to describe itself as independent: [Issue #4 comment 6697833256](https://github.com/ErenTahiroglu/Security-Assurance-Runner/issues/4#issuecomment-6697833256).

## P2-01: signed exit code versus observed process status

Prior behavior checked Docker `State.ExitCode == 23`, but the separately signed witness could declare another nonzero exit such as `1`, pass the existing test-only witness importer, and be consumed. This was a concrete integrity gap despite `operational_pass=false`.

**Correction:** the Rust coordinator still requires actual `docker inspect` termination evidence (`Running=false`, `OOMKilled=false`, no runtime error and the known inert-helper `23` exit), but now parses the already signature-verified witness statement and additionally requires its `exit_code` to equal the **observed** value. An exact signed `exit_code=1` counterexample is included in the Linux Docker integration test; it must return `PipelineRefusal::WitnessExitMismatch` after actual helper execution and container cleanup. This does not establish trusted production process attestation.

## P2-02: observable cleanup failure on error paths

Previously only the successful path checked removal; `Drop` performed best-effort Docker removal but suppressed the command outcome on early failure/timeout.

**Correction:** all code after installing the `ContainerGuard` now runs within a bounded result-producing execution closure. The coordinator **always attempts checked cleanup before returning either success or an execution error**, including create/inspect/start timeout, unexpected exit, witness disagreement and invalid output. Checked removal requires observed absence of the named container and a responsive Docker daemon; a known created container also requires a successful removal command. Cleanup errors take precedence and surface as `PipelineRefusal::CleanupFailed`. Best-effort recovery removal is attempted on failure; the original failure is **not** silently reclassified as PASS. A final `Drop` remains a panic-path fallback, not evidence of verified cleanup.

The two additional *test-only* modes inject a simulated first Docker-remove failure after either an otherwise successful helper output or an early intentional helper-exit failure. Both are required to return `CleanupFailed` and leave no container when recovery succeeds. This simulates a failing cleanup command; it is NOT an assertion that the GitHub runner's Docker daemon actually failed spontaneously. Persistently unavailable Docker cleanup is still reportable but cannot be guaranteed to succeed.

## Exact source and CI evidence

Code changes are limited to `src/inert_pipeline.rs` and `tests/pipeline_inert_linux.rs` plus rustfmt/Clippy-only fixes. Neither workflow was expanded to invoke a real scanner.

- [Rust CI 42309333424, attempt 1](https://github.com/ErenTahiroglu/Security-Assurance-Runner/actions/runs/42309333424), exact `2b38ea8e0bc71eaaf3df9a5ec48df25d51de17ac`: Linux x64, Windows x64, macOS ARM64 all SUCCESS with `cargo fmt --all -- --check`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked`, `cargo build --locked`; **49/49 ordinary Rust tests per OS**.
- [Linux scanner-disabled preflight 42309333458, attempt 1](https://github.com/ErenTahiroglu/Security-Assurance-Runner/actions/runs/42309333458), exact `2b38ea8e0bc71eaaf3df9a5ec48df25d51de17ac`: **17/17 Python tests**, **1/1 explicitly executed Linux inert-helper Docker integration test** in 7.50 s, plus local network positive/none negative, filesystem and forced timeout/cleanup probes. The Docker-dependent test is intentionally ignored in the ordinary Rust suite and explicitly executed in Linux preflight; its one pass covers multiple negative branches within that test function.

Earlier transient intermediate commits failed `rustfmt` or Ubuntu Clippy with `-D warnings`. These were repaired rather than waived; the final exact-SHA checks above are green.

## Trust and replay limits

The process is an invented static C helper with artificial report data, **not Gitleaks**. The signed test keys/plan are fixture assumptions. Same-instance replay prevention is not durable. Docker container controls do not establish production host or provider attestation. The operational receipt continues to report `actual_gitleaks_executed=false`, `production_process_attested=false`, `operational_pass=false` and `policy_decision=INDETERMINATE`.

The original local checkout and unstaged PDF-protection `.gitignore` are not altered by remote GitHub commits; this remote-only session cannot inspect the local worktree.

## Required next step

An **actually separate reviewer** must inspect exact-SHA source and CI logs, challenge the signed-exit counterexample, error-path cleanup precedence/injection and no-leak/no-authority boundaries. Do not equate an author-associated review or assistant-authored correction with independent approval. Keep Issue #4 and roadmap #11 OPEN, `main` frozen. No new Gitleaks acquisition/execution or real repository scan is authorized.
