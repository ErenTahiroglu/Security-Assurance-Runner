# GOV-01 draft implementation report

**Status:** GOV-01 R1 author candidate; independent review and owner disposition pending. The executable is not a scanner or operational trust verifier. Exact candidate SHA and CI results are recorded in Issue #3.

## Recovery preflight gap assessment

The preserved draft was inspected on `development` at `2cda6b94d2b51595f3ee0368795fc70e92b5c637`; the remote branches matched. Local `cargo test --locked` reproduced five passing integration tests on Darwin arm64. These are baseline observations, not evidence of later recovery changes.

| Component | Existing implementation | Actual baseline validation | Missing work |
|---|---|---|---|
| Manifest parser | Bounded typed JSON, identity and list checks | `bounded_and_strict_manifest` passed | Boundary coverage and security-contract integration |
| CLI | Version and inspection; no root, refuses | Compiled as part of local test run | CLI behavior and receipt testing |
| Trust verification | Ad hoc synthetic Ed25519 helper inside integration test | One synthetic test passed | Reusable typed verification, purpose binding and full negative cases |
| Evaluation | Synthetic required-check decision over caller booleans | Three synthetic evaluation tests passed | Derive evidence validity from bounded bytes |
| Stage receipts | Absent | None | Binding and deterministic reconciliation |
| Negative tests | Five integration tests | Five passed locally | Complete RT01 cases and stage/report adversarial cases |
| CI | No workflow | GitHub API reported zero runs | Exact-SHA Linux, Windows and macOS arm64 validation |

## Recovery implementation

The retained parser bounds input to 65,536 bytes, check collections to 64, tokens to 128 bytes, and rejects unknown or duplicate typed fields, invalid identity and unsupported versions. The `version` CLI is inert; `inspect` reads stdin and always refuses valid requests with `NO_ENROLLED_AUTHORITY`. Exit codes are 0 for version, 2 for invalid usage/input, 3 for missing authority and 5 for input read failure. Repository identity is caller-declared and is not authenticated by a provider.

`trust::verify_synthetic_policy` verifies Ed25519 signatures over DSSE v1 PAE type and exact payload bytes with an explicitly supplied synthetic key and context, then checks version, purpose, issuer role, repository, policy digest, sequence, interval and supplied freshness/revocation state. It accepts raw payload and signature bytes, not a full DSSE JSON envelope. No fixture key is in the CLI and no operational enrollment, signing or authenticated owner approval exists. Context freshness and time are assumptions, not observed guarantees. Strict verification rejects weak keys; the crate documents that full RFC/NIST point validation criteria are not supported.

`reconcile::reconcile` requires a verified synthetic policy matching the plan's repository, policy ID, digest and sequence; absence or mismatch yields INDETERMINATE. It accepts a controlled synthetic plan and untrusted stage artifact bytes, checks SHA-256 digests and strict JSON reports against repository, commit, policy, parent run, plan, stage, attempt, mode, location, artifact ID and expected synthetic status source. Check statuses and findings are derived from parsed bytes rather than a caller's validity flag. A missing, corrupt, skipped, duplicated, conflicting or mismatched stage cannot yield synthetic PASS. Outputs are marked `test_only`; no provider, scanner, OS isolation, host integrity or independent external verification is claimed. Plans and digest expectations are test fixtures, not authenticated authorities; verification and reconciliation do not establish operational trust.

Execution, policy and coverage are separate. A valid synthetic blocking finding may produce BLOCK even when another stage is incomplete. A refused CLI invocation does not execute checks or produce a finding-based BLOCK. Active categories are rejected in synthetic plans.

## Dependency provenance

Rust 1.99.1 is pinned for the prototype; it was exercised locally on Darwin arm64. Cargo registry metadata reviewed 2026-10-30 reports:

| Crate and locked version | Purpose and features | License / stated MSRV | Primary source |
|---|---|---|---|
| serde 1.0.229 | Typed strict parsing; derive | MIT OR Apache-2.0 / 1.56 | [serde](https://github.com/serde-rs/serde) |
| serde_json 1.0.154 | Bounded JSON parsing | MIT OR Apache-2.0 / 1.71 | [serde_json](https://github.com/serde-rs/json) |
| sha2 0.10.9 | SHA-256 artifact and policy digests | MIT OR Apache-2.0 / not specified in metadata | [RustCrypto hashes](https://github.com/RustCrypto/hashes) |
| ed25519-dalek 3.0.0 | Synthetic verification; default features off, zeroize on | BSD-3-Clause / 1.85 | [dalek](https://github.com/dalek-cryptography/curve25519-dalek), [verification API](https://docs.rs/ed25519-dalek/3.0.0/ed25519_dalek/struct.VerifyingKey.html) |

`Cargo.lock` has 38 third-party packages including platform-specific and build dependencies; `cargo metadata --locked` reports licenses including MIT, Apache-2.0, BSD-3-Clause, BSD-1-Clause, Unlicense and Unicode-3.0. It also includes sha2 0.11.1 through dalek (MSRV 1.88). These are package metadata, not a legal compatibility determination; preserve the applicable dependency texts and notices for distribution. No third-party source from DefectDojo, GUAC, ECE or ATM was copied. See [notices](../THIRD_PARTY_NOTICES.md).

Not implemented: real enrollment, issuer custody or revocation service, authenticated provider identity, active-test authorization, external scanner report parsers, process isolation, ECE integration, external verification, AI and real security testing. A compromised host can falsify the clock, root, execution and output. Local sequence floors do not prevent rollback of the whole host. GitHub branch protection is not configured.

Reproduce with `cargo fmt --all -- --check`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked`, and `cargo build --locked`. Actual test totals and exact-SHA CI outcomes are recorded in Issue #3. A green build is not security acceptance or merge protection.
