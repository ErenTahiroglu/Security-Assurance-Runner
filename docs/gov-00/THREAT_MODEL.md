# Threat model

**Status:** Proposed threat register; likelihood labels are preliminary exposure estimates, not measured probabilities. Mitigations are unimplemented. Negative tests are future requirements.

| ID / threat | Attacker; boundary; impact; exposure | Proposed mitigation | Required negative test | Residual / milestone |
|---|---|---|---|---|
| T-01 False PASS or self-certification | Contributor/automation; policy boundary; unsafe merge; High | Independent state dimensions; no PASS on missing evidence; owner-controlled promotion | Missing/failed/stale check never yields PASS | Human process remains; GOV-04/V1 |
| T-02 Scanner disabled/skipped | Config author; manifest/adapter; blind spot; High | Declare expected checks and explicit skip/unsupported states | Disabled required adapter blocks or yields INCOMPLETE | Inventory drift; GOV-01/04 |
| T-03 Wrong repo/commit | Replay/substitution; identity boundary; evidence misbinding; High | Bind receipt to canonical repo identity and full commit SHA | Substitute repo/SHA is rejected | Trust in source provider; GOV-05 |
| T-04 Stale CI result | Race/replay; CI boundary; wrong candidate accepted; High | Bind run to event/candidate and policy digest; freshness rule | Old run cannot satisfy new candidate | Provider semantics; GOV-04 |
| T-05 Malicious scanner output | Compromised tool/input; parser boundary; code execution or false findings; High | Treat output as hostile; schema/size limits; non-executing parsers | Malformed/deep/oversized documents safely fail | Parser bugs; GOV-02 |
| T-06 Prompt injection in source/report | Attacker-controlled text; future AI boundary; disclosure/action; Medium in v2 | AI off default; no tool authority; isolated context and output validation | Embedded instruction cannot cause call/write/network | Model residual; V2-AI |
| T-07 Unauthorized external testing | Operator/config error; authorization boundary; legal/service harm; High | Explicit target ownership/authorization and allowlist | Out-of-scope host is refused | DNS/redirect complexity; GOV-03 |
| T-08 Unapproved egress | Redirect/SSRF/tool behavior; network boundary; data loss/impact; High | Egress controls outside job config; resolve/redirect revalidation | Redirect/DNS change cannot escape scope | Network stack gaps; GOV-03 |
| T-09 Unsafe subprocess | Malicious path/argument; process boundary; arbitrary execution; High | Fixed executable, argument vector, no shell, controlled env | Shell metacharacters remain inert | Tool itself still runs; GOV-01 |
| T-10 Compromised dependency | Upstream compromise; build boundary; code compromise; High | Pin/verify dependencies, provenance, review updates | Tampered artifact rejected under future policy | Upstream trust; all phases |
| T-11 Confusion/typosquatting | Maintainer/dependency resolver; supply chain; compromise; Medium | Lock exact coordinates, trusted registries, review namespace | Lookalike dependency does not resolve silently | Ecosystem limits; GOV-02 |
| T-12 False positive/negative misclassification | Tool or normalizer; evidence boundary; wrong decision; High | Preserve raw output, source/version/confidence, explicit disposition | Altered severity/confidence is traceable | Detection limits; GOV-02/04 |
| T-13 Severity manipulation | Output author; normalization/policy; bypass; High | Preserve native severity and separate policy mapping | Changed severity changes audit trail and policy result | Scoring subjectivity; GOV-04 |
| T-14 Stale offline vulnerability data | Offline user; database boundary; missed/new CVEs; High | Record source, version, timestamp and freshness; unknown state | Expired DB yields stale/unknown, not clean | No universal freshness guarantee; GOV-02 |
| T-15 Secrets in reports | Scanner/source; report boundary; credential exposure; High | Minimize snippets, redaction, access boundaries | Canary secret absent from exported report | Redaction false negatives; GOV-02 |
| T-16 Archive/parser abuse | Malicious archive/report; ingestion boundary; traversal/DoS; High | Path normalization, limits, no extraction where possible | Traversal, bomb, symlink, entity payload rejected | Parser defects; GOV-02 |
| T-17 Cross-run substitution/collision | Concurrent jobs; evidence storage; wrong artifact association; Medium | Unique run IDs, atomic isolated dirs, content digests | Parallel identical names cannot overwrite/mix | Storage implementation; GOV-01/04 |
| T-18 Policy bypass/unauthorized exception | Insider/config change; governance; missed block; High | Trace policy digest, scoped reason/reviewer/expiry; separate authorization | Expired or broadened exception rejected | Authorized reviewer risk; GOV-04 |
| T-19 Misleading standards claim | Report author; mapping boundary; false compliance; High | Map individual evidence and limitations; prohibit blanket claims | Partial tests cannot label framework compliant | Human assessment needed; GOV-00/04 |
| T-20 ECE/SAR boundary confusion | Consumer; verification boundary; overstated assurance; High | Explicit claim types and verifier limits | Valid evidence integrity cannot imply scan completeness | Consumer interpretation; GOV-05 |
| T-21 AI while disabled | Hidden dependency/provider; AI boundary; data transfer; High | No provider dependency/calls in v1; explicit invocation audit | Network capture shows no model request when disabled | Runtime supply chain; V2-AI |
| T-22 Cross-platform isolation mismatch | Platform/runtime; execution boundary; escape; High | Capability matrix; unsupported-mode refusal; host-specific tests | Same policy cannot silently weaken on Windows/macOS | Platform variance; GOV-03 |
| T-23 Unauthorized other-repository access | Bug/config; filesystem boundary; data disclosure/modification; High | Explicit repository root, least privilege, no broad workspace traversal | Neighbor repository sentinel remains unread/unmodified | Host permissions; GOV-01 |
| T-24 Incomplete/misleading coverage | Adapter failure or unsupported language; coverage boundary; false assurance; High | Declare supported inputs, skipped scope and uncertainty | Empty/unrecognized input reports incomplete | Tool coverage opaque; GOV-04 |

All mitigations remain proposals. None of these tests ran in GOV-00.
