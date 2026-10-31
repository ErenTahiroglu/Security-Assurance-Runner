# GOV-02 DESIGN R0 — independent review handoff

**AUTHOR HANDOFF ONLY; independent review and owner decision pending.** Exact source SHA and CI result are recorded in [Issue #4](https://github.com/ErenTahiroglu/Security-Assurance-Runner/issues/4); compare `git rev-parse HEAD` and CI head. This document does not authorize GOV-02 implementation, real scanner use, downloading binaries/rules/databases or a trusted security PASS.

Read [tool evaluation](GOV_02_TOOL_EVALUATION.md), [execution boundaries](GOV_02_ADAPTER_TRUST_AND_EXECUTION.md), [evidence contract](GOV_02_EVIDENCE_AND_COVERAGE_CONTRACT.md) and [G02-RT01–RT20](GOV_02_NEGATIVE_TEST_PLAN.md), then cross-check the accepted [GOV-01 security boundary](../gov-01/GOV_01_SECURITY_BOUNDARIES.md) and [trust bootstrap](../gov-00/TRUST_BOOTSTRAP_AND_POLICY_AUTHORITY.md).

## Conditional recommendation and owner decisions

**Option A:** after independent design review, consider separately authorizing one fixture-only Gitleaks v8.30.1 JSON-format adapter, with invented nonsecret fixtures, strict bounded parser and normalization; no scanner execution or tool download. OSV-Scanner v2.7.0 remains a later conditional candidate, not part of the first implementation authorization. Gitleaks v8 is feature-complete and its JSON output may not establish rule/file coverage; Betterleaks v1/v2 behavior and format require additional research. If the output cannot establish the required coverage, preserve INDETERMINATE rather than claim PASS.

Owner decisions after review: (1) authorize or reject that exact fixture-only scope; recommended authorize only after review; (2) approve rule/config source and permitted distribution only after file-level license assessment; recommended independently authored inert fixtures, no rule bundling; (3) separately approve any later executable acquisition/execution and platform containment only after concrete test evidence; recommended defer; (4) set offline DB freshness and trusted refresh authority when SCA is separately proposed; recommended no default without evidence. These are decisions, not approvals.

## Questions for independent reviewer

1. Can repository-controlled ignore/config, substituted binary, untrusted plan expectation or process output manufacture PASS? Are missing rules/files and exit-0 errors handled as incomplete?
2. Is the raw-secret boundary safe across logs, restricted storage, redacted output, error paths and digests? Are retention and access assumptions explicit?
3. Are GitHub CodeQL terms, Gitleaks Action versus CLI, Semgrep rules and OSV database rights accurately qualified? Do unknowns prevent unsupported selection?
4. Can path/URL/archive handling, egress, symlinks, timeouts and child processes be contained across all required platforms? Which controls require real tests before use?
5. Are synthetic records, scanner claims, provenance verification, policy decision and owner release authority separate? Do negative tests specify falsifiable future oracles?

No scanner was installed, executed or tested; no scanner data, rules, vulnerability DB or third-party implementation code was added. Existing development CI, if triggered, tests only the GOV-01 Rust PoC and cannot accept this architecture. Issue #4 stays open; main remains frozen; the next action is independent design review, not GOV-02 coding.
