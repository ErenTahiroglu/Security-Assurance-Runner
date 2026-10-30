# Standards and control mapping

**VERIFIED SOURCE FACT:** Official pages reviewed on 2026-10-30 identify OWASP Top 10:2025 as released; ASVS 5.0.0 as stable (published 2025-05-30); WSTG stable as a methodology guide with versioned identifiers; NIST SSDF 1.1, CSF 2.0 and SP 800-61 Rev. 3 final; and CycloneDX 1.7 as current. OWASP announced the LLM Top 10 2026 on 2026-09-02 and the Agent Control Standard on 2026-09-01. The Agentic Applications Top 10 release announced 2025-12-10 is referenced as the 2026 edition. Treat their status as published project guidance/standard as described by OWASP, not as a regulatory certification. NIST/OpenSSF SLSA materials are supply-chain guidance/specifications, not blanket assurance.

| Source | Applicability proposal | Example evidence mapping | Automated? | Status |
|---|---|---|---|---|
| OWASP Top 10:2025 | Risk taxonomy for web app scope | Map findings to A01–A10 where evidence supports | Partial; category mapping is not conformance | Requires assessment |
| OWASP ASVS 5.0.0 | Requirement catalog for selected app scope | Versioned requirement ID + test/evidence and limitation | Mixed; technical checks and manual review | Applicable by selected profile |
| OWASP WSTG stable/versioned | DAST test methodology | Version-specific WSTG case and execution result | Some steps automatable | Applicable to authorized web testing |
| OWASP Cheat Sheet Series | Implementation guidance | Link to applicable guidance; not control certification | Mostly manual | Informative |
| NIST SSDF 1.1 | Secure development process | Practice/task references and organizational evidence | Governance + some automation | Requires assessment |
| NIST CSF 2.0 | Organizational risk outcomes | Outcome mapping and evidence owner | Mainly governance | Requires assessment |
| NIST SP 800-61 Rev. 3 | Incident response process | Operational process evidence | Governance/process | Limited product applicability |
| SARIF 2.1.0 | Static-analysis interchange | Parse/export results | Machine format, not control | Candidate |
| CycloneDX 1.7 | BOM/supply-chain data | BOM and component relationships | Machine-readable, quality varies | Candidate |
| SPDX | SBOM/license metadata | Package and license records | Machine-readable, quality varies | Candidate; select version later |
| NIST OSCAL | Control catalogs, plans, assessments | Import/export structured assessment data | Format automation only | Defer unless consumer need |
| OpenSSF Scorecard / SLSA | Supply-chain posture/provenance | Record exact source, score/spec version and limits | Partial | Assess per signal |
| OWASP Top 10 for LLM Applications 2026 | v2 AI scope only | Pin exact published edition and identifiers | Mixed/manual | Officially announced 2026-09-02 |
| OWASP Top 10 for Agentic Applications 2026 | v2 AI scope only | Pin ASI identifiers and edition | Mixed/manual | Released 2025-12-10 for 2026 edition |
| OWASP Agent Control Standard (ACS) | Candidate v2 runtime-control reference | Assess hooks and policy claims against target agent frameworks | Requires runtime evidence | Announced/donated to project 2026-09-01; maturity/version needs assessment |

Mapping outcomes must be `APPLICABLE`, `NOT_APPLICABLE`, `REQUIRES_ASSESSMENT`, `DEFERRED`; evidence method separately `AUTOMATED`, `MANUAL`, `GOVERNANCE`. A scanner run never demonstrates full OWASP, ASVS, NIST or other framework compliance. IDs and versions must be pinned; no copyrighted standard text is reproduced.
