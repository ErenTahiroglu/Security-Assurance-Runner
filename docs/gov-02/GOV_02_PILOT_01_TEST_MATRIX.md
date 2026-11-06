# GOV-02 PILOT-01 — evidence and negative-test matrix

**Correction under independent review:** the original native report is unavailable; the historical report row below describes the original weaker oracle, not retrospective verification under the corrected oracle. The corrected inspector requires exact `REDACTED` values, fixture-specific location and no-commit fingerprint consistency. Synthetic negative tests cover empty, unrelated and inconsistent secret/match values, missing fields, invalid coordinates, wrong rule/file, duplicate keys/findings, null, missing, truncated and oversized input, and output redaction. The arming-tree test is synthetic and does not reactivate the removed scanner workflow.

| Check | Execution evidence | Result / limit |
|---|---|---|
| Source/run chain and one-shot trigger | [41482929656](https://github.com/ErenTahiroglu/Security-Assurance-Runner/actions/runs/41482929656) job 125405680860, exact trigger commit `429e08f182c7d01e2a158968cf963817b09cb0f1` | EXECUTED / verified; Git actor+marker are selectors, not authenticated owner signature |
| Trusted archive content pin | Official release asset digest and `PILOT_RELEASE_ARCHIVE_DIGEST_MATCH` | EXECUTED / content integrity; no signed publisher proof |
| Wrong archive hash | [41480656932](https://github.com/ErenTahiroglu/Security-Assurance-Runner/actions/runs/41480656932) refused before execution | EXECUTED NEGATIVE, original expected-hash typo corrected |
| Wrong scanner mount count | [41481960819](https://github.com/ErenTahiroglu/Security-Assurance-Runner/actions/runs/41481960819) refused before execution | EXECUTED NEGATIVE, seven new spec regression tests |
| Docker HostConfig and mounts | `PILOT_SCANNER_CONTAINER_SPEC_VERIFIED` at real run | EXECUTED: exact command, 3 mounts, no network, read-only source/config, nonroot, caps dropped, fixed resource limits |
| Independent local network positive/negative | `PREFLIGHT_LOCAL_NETWORK_POSITIVE_OK` and `PREFLIGHT_NETWORK_NONE_NEGATIVE_OK` | EXECUTED for controlled local bridge endpoint; not comprehensive no-egress proof |
| Filesystem read-only / expected output | `PREFLIGHT_FILESYSTEM_OK` | EXECUTED for scope-tested paths, not arbitrary host escape |
| Timeout and forced cleanup probe | `PREFLIGHT_TIMEOUT_CLEANUP_OK` | EXECUTED using inert test executable; not a malicious scanner runaway |
| Synthetic rule and corpus | `PILOT_CORPUS_SYNTHETIC_ONLY`; expected rule and two fixture files validated | EXECUTED with custom artificial pattern |
| Real scanner and exit | `PILOT_SCANNER_NATIVE_EXIT=23` | EXECUTED: configured finding code, not universal scanner success |
| Native JSON report | exact one approved synthetic positive, none expected on negative file; digest recorded | EXECUTED; no raw report artifact |
| Malformed, duplicate and non-matching report | 6 Python report tests at [41482427458](https://github.com/ErenTahiroglu/Security-Assurance-Runner/actions/runs/41482427458) | EXECUTED SYNTHETIC tests, fail closed |
| Missing/writable/unapproved mount, wrong network or argv | 7 Python Docker spec tests at same run | EXECUTED SYNTHETIC tests; actual scanner configuration separately checked |
| Existing Rust regression | [41482427463](https://github.com/ErenTahiroglu/Security-Assurance-Runner/actions/runs/41482427463) | EXECUTED CI Linux/Windows/macOS; 38 tests/OS |
| Cryptographically authenticated owner policy and independent publisher signature | None implemented | DEFERRED — not implied by pilot |
| Actual hostile symlink/archive or kernel container escape | Not exercised | DEFERRED — requires separate authorization and containment model |
| Real repository vulnerability coverage, SAST, SCA, product PASS | Not attempted | OUT OF SCOPE |

All test markers are invented and nonfunctional. Scanner-only pilot code has no arbitrary repository scan or real credential validation. The one-time runner workflow and marker were removed at `74702276cee637c61ec08c7c75fa49ab46166d2a`.
