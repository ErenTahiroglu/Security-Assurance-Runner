# GOV-02 PILOT-01 — Linux x64 real Gitleaks execution report

**Author classification:** `GOV_02_PILOT_01_PASS_READY_FOR_INDEPENDENT_REDTEAM` for a single **synthetic-only** scanner invocation; independent source/security review is NOT yet accepted. Report assembled 2026-11-02 from direct GitHub Actions job logs and immutable Git SHAs.

## Exact immutable records

| Milestone | SHA / run |
|---|---|
| Previously accepted R2 | `a2ef0261d9361b8c4799ca462c845860396d09db` |
| First hosted Docker preflight | [41358373911, attempt 1](https://github.com/ErenTahiroglu/Security-Assurance-Runner/actions/runs/41358373911), code SHA `8a61cd2042bc81c43d2d962cae96ce3bef032ecf` |
| Final pilot implementation + 13 Python tests | `c16d9facb01607e6ae33185569140b6f9fd70d8c` |
| Final scanner-disabled preflight | [41482427458, attempt 1](https://github.com/ErenTahiroglu/Security-Assurance-Runner/actions/runs/41482427458) |
| Source pin correction and final arm | `ed808d001acc72a56308deb15b6a33be0d531d8c` / `4e970315c7bd2a07317cfeeb59ce7b4142078779` |
| **Only actual Gitleaks invocation** | **[41482929656, attempt 1](https://github.com/ErenTahiroglu/Security-Assurance-Runner/actions/runs/41482929656)**, trigger `429e08f182c7d01e2a158968cf963817b09cb0f1`, Linux x64 job `125405680860` |
| Cleanup / trigger removal | `74702276cee637c61ec08c7c75fa49ab46166d2a` |
| Frozen main | `956ae354e0e02e05154acc71a0158f5bf96f02fa` |

The separate existing Rust validation at final implementation SHA [41482427463 attempt 1](https://github.com/ErenTahiroglu/Security-Assurance-Runner/actions/runs/41482427463) succeeded on Ubuntu Linux x64, Windows x64 and macOS ARM64 (38 existing Rust tests per OS, fmt/Clippy/build). Synthetic-only Python report and Docker specification tests: **13/13** and actual Linux preflight job **PASS** at the same source SHA. The cleanup SHA has a separate [Rust CI run 41483426847](https://github.com/ErenTahiroglu/Security-Assurance-Runner/actions/runs/41483426847); do not assume its success without checking that run.

## Release identity and integrity

Pinned official asset: `gitleaks_8.30.1_linux_x64.tar.gz` at [official v8.30.1 release](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1). Source-verified SHA-256: `551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb`. The successful job recorded `PILOT_RELEASE_ARCHIVE_DIGEST_MATCH` before bounded, symlink-free extraction and ELF x86_64/static check. Extracted executable observed SHA-256: `88f91962aa2f93ac6ab281d553b9e125f5197bbbce38f9f2437f7299c32e5509`. These are observed content identities, not independent signed publisher identity or a production policy trust root.

## Corpus, configuration and invocation

The disposable input had exactly:
- `positive.txt`: the invented, nonfunctional `SAR_INERT_DEMO_` test marker.
- `negative.txt`: ordinary benign text not matching that pattern.
- An independent original minimal TOML config, rule ID `sar-pilot-inert-rule`, matching only the artificial pattern `SAR_INERT_DEMO_[A-Z0-9]{8}`.

The harness refuses unexpected source/config entries and files, symlinks and changed fixture contents. No real repository, Git history, credentials or user data were scanned. `.gitleaksignore` and `.gitleaks.toml` cannot be included in the two-file source inventory.

Fixed command arguments, observed in the reviewed harness: `dir /input --config=/config/pilot.toml --report-format=json --report-path=/output/report.json --exit-code=23 --no-banner --redact=100 --ignore-gitleaks-allow --max-archive-depth=0 --max-target-megabytes=1`.

## Isolation: actual observations

Each real scanner run begins by re-executing the separate scanner-disabled Docker preflight. The actual successful job showed:
`PREFLIGHT_LOCAL_NETWORK_POSITIVE_OK`, `PREFLIGHT_NETWORK_NONE_NEGATIVE_OK`, `PREFLIGHT_FILESYSTEM_OK`, `PREFLIGHT_TIMEOUT_CLEANUP_OK`, and `GOV_02_PILOT_01_SCANNER_DISABLED_PREFLIGHT_PASS`.

The scanner container's actual HostConfig passed strict checks for `--network none`, read-only root, non-root UID, dropped capabilities, no-new-privileges, 128 MiB memory/swap, 0.5 CPU, 32 PIDs, fixed entrypoint/command and three controlled bind mounts: read-only synthetic source, read-only config and restricted writable report destination. It inherited no GitHub/token environment variables via Docker image configuration; neither the checkout nor Docker socket was mounted. The runner enforced a 60-second scanner timeout and cleaned up container/image and disposable files. This is bounded evidence of specified Docker controls, **not** a formal container escape, kernel, hypervisor or overall host-security proof.

## Actual scanner result

The successful job recorded `PILOT_SCANNER_CONTAINER_SPEC_VERIFIED`, followed by **`PILOT_SCANNER_NATIVE_EXIT=23`** and the sanitized strict report-inspector result:
`{"coverage_verified":false,"findings":1,"native_report_authenticated":false,"operational_pass":false,"status":"EXPECTED_INERT_FINDING_OBSERVED","synthetic_only":true}`.

Raw report digest in the disposable runner: `6ed6107768b779cca7d3eb32789240d2b689bc11a68dd1deca43d591310f1ce4`. The strict inspector requires a JSON array with exactly one finding, the original approved rule, the positive file and line 1; no finding for the negative file. It rejects duplicates, malformed/missing/null/oversized reports, wrong rule/file and unsupported missing sensitive native fields. Native report/stderr were not logged or uploaded; only sanitized booleans/count, executable and report digests were printed. The observed report digest is **not** separately authenticated evidence of real-world scanner completeness.

The scanner was invoked **once**; earlier authorized-workflow attempts were **refused before executable invocation**:
- [41480656932 attempt 1](https://github.com/ErenTahiroglu/Security-Assurance-Runner/actions/runs/41480656932): preflight passed, but archive hash validation stopped because the formerly recorded expected digest mistakenly contained `...d62a0b982...` instead of correct `...d62a0d982...`.
- [41481960819 attempt 1](https://github.com/ErenTahiroglu/Security-Assurance-Runner/actions/runs/41481960819): archive digest matched and extracted binary was identified, but three-mount scanner configuration was incorrectly compared against a two-mount-only validator; it refused before `docker start`.
- [41482929656 attempt 1](https://github.com/ErenTahiroglu/Security-Assurance-Runner/actions/runs/41482929656): real scanner actually ran and passed the inert experiment.

The code fixes remained fail-closed and added seven Docker specification negative tests, for a total of 13 independent Python tests (6 report inspector + 7 Docker spec), in addition to the existing 38 Rust tests.

## Security acceptance boundary

**Pilot engineering PASS:** controlled real Gitleaks invocation against a fabricated corpus and fixed, single-source rule with observed expected finding; no production policy verdict.

**NOT established:** general Gitleaks detection performance, real-world secret/zero-finding completeness, independently authenticated publisher signing/root, full filesystem or network confinement against adversarial kernel attacks, real host isolation on Windows/macOS, robust native report provenance, general SAST/SCA, automatic production PASS/BLOCK, or scanner integration into SAR policy decisions.

The one-shot scanner workflow and marker were removed by cleanup commit `74702276cee637c61ec08c7c75fa49ab46166d2a`; this source head contains no workflow permitting another real Gitleaks run. The normal scanner-disabled preflight remains. No change to `main`, branch protection, or releases was authorized.

**Next gate:** independent Red Team review of exact execution SHA, cleanup and evidence before owner accepts the completed synthetic pilot and authorizes any real-depot scanner integration.
