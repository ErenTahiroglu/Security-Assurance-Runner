# Roadmap and acceptance gates

**Status:** ARCHITECTURAL PROPOSAL. No phase below GOV-00 is complete or authorized by this package.

| Phase | Proposed outcome | Gate |
|---|---|---|
| BOOTSTRAP-00 | Initial docs/license and two branches | Identity, branch and clean-tree evidence |
| GOV-00 | Architecture, threat, standards, policy and provenance foundation | Independent Red Team review; explicit owner disposition |
| GOV-01 | Bounded, reversible Rust-first runner-core proof-of-concept and deterministic contracts (proposed only) | Starts only after independent GOV-00 acceptance and explicit owner authorization. Before trusted PASS: independently enrolled trust root; authenticated policy/issuer and repository binding; fail-closed missing/invalid/stale approval; mandatory-check/coverage semantics; clearly synthetic negative fixtures. Candidate SHA, deterministic tests and platform evidence required. Final runtime selection remains a later evidence-based decision. |
| GOV-02 | Selected SAST/SCA/secret adapters | Pinned tools, hostile output tests, source/coverage declarations |
| GOV-03 | Authorized isolated DAST and fuzzing | Scope/egress enforcement, isolation evidence, authorization tests |
| GOV-04 | CI/local/hybrid execution, policy and reports | Missing/stale/failed checks fail safely; policy and exception tests |
| GOV-05 | ECE interoperability | Versioned adapter contract; ECE verification limits preserved |
| V1-ACCEPTANCE | Independent assessment of declared v1 scope | Independent Red Team review, residual risks, owner approval |
| V2-AI | Optional AI review and adversarial agent testing | Separate authorization, provider/privacy and agent boundary review |

Sequencing may change if prototypes establish dependency order; record changes as ADRs. GitHub Issue [#11](https://github.com/ErenTahiroglu/Security-Assurance-Runner/issues/11) is the owner's authoritative status index and records existing milestone Issues #1–#11, including planned/blocked phases. This later explicit owner instruction supersedes the original suggestion not to pre-open future issues. Update the existing phase issues with exact evidence and blockers; do not create duplicates or infer implementation authorization from their existence. GOV-00 Issue #1 remains open until independent review and explicit owner disposition; author self-review cannot close it.
