# Roadmap and acceptance gates

**Status:** ARCHITECTURAL PROPOSAL. No phase below GOV-00 is complete or authorized by this package.

| Phase | Proposed outcome | Gate |
|---|---|---|
| BOOTSTRAP-00 | Initial docs/license and two branches | Identity, branch and clean-tree evidence |
| GOV-00 | Architecture, threat, standards, policy and provenance foundation | Independent Red Team review; explicit owner disposition |
| GOV-01 | Minimal executable runner core and deterministic contracts | Candidate SHA, deterministic negative tests, cross-platform boundary evidence |
| GOV-02 | Selected SAST/SCA/secret adapters | Pinned tools, hostile output tests, source/coverage declarations |
| GOV-03 | Authorized isolated DAST and fuzzing | Scope/egress enforcement, isolation evidence, authorization tests |
| GOV-04 | CI/local/hybrid execution, policy and reports | Missing/stale/failed checks fail safely; policy and exception tests |
| GOV-05 | ECE interoperability | Versioned adapter contract; ECE verification limits preserved |
| V1-ACCEPTANCE | Independent assessment of declared v1 scope | Independent Red Team review, residual risks, owner approval |
| V2-AI | Optional AI review and adversarial agent testing | Separate authorization, provider/privacy and agent boundary review |

Sequencing may change if prototypes establish dependency order; record changes as ADRs. Do not open speculative issues for every future phase. GOV-00 should have one primary tracking issue if authenticated write access exists and no equivalent exists. It must not be closed on author self-review.
