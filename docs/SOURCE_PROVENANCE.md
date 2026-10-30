# Source provenance

Research snapshot prepared 2026-10-30. Links are sources, not endorsements; mutable pages must be rechecked at implementation time.

## Repositories
- SAR: https://github.com/ErenTahiroglu/Security-Assurance-Runner (REST ID 1439402924; owner ErenTahiroğlu).
- DefectDojo reference commit: https://github.com/DefectDojo/django-DefectDojo/commit/c360df03a9399cbe6b26138bd0289949c27eb732 (verified exact SHA; BSD-3-Clause).
- GUAC reference commit: https://github.com/guacsec/guac/commit/a3f0a4df51abcf271221cf9c400de3158d9c20fa (verified exact SHA; Apache-2.0).
- ECE historical `main` bootstrap: https://github.com/ErenTahiroglu/Evidence-Checkpoint-Engine/tree/bead6837e1ec03c8fe1ac3c8d09fd374fb8b0e02 (rechecked 2026-10-30; README describes documentation-only bootstrap).
- ECE independently accepted GOV-01 offline verifier: https://github.com/ErenTahiroglu/Evidence-Checkpoint-Engine/tree/415990746d5bbd3756f743b4b5a7673b36228567; acceptance and limitations recorded in https://github.com/ErenTahiroglu/Evidence-Checkpoint-Engine/issues/3#issuecomment-6516966400.
- ECE current development observation: https://github.com/ErenTahiroglu/Evidence-Checkpoint-Engine/tree/ccde36586a4df170db38f018d6eb8a8a653de99f (rechecked 2026-10-30). Five commits beyond accepted GOV-01; includes GitHub adapter source/tests and a build workflow. These changes are unaccepted GOV-02 development; issue #4 remains open: https://github.com/ErenTahiroglu/Evidence-Checkpoint-Engine/issues/4.
- ECE integration contract in historical main is a draft; no accepted stable SAR-facing adapter contract was established by this review. Changing development does not change that status by itself.

## Standards sources
- OWASP Top 10:2025: https://top10.owasp.org/2025/
- ASVS release/status: https://asvs.owasp.org/
- WSTG: https://wstg.owasp.org/
- OWASP Cheat Sheet Series: https://cheatsheetseries.owasp.org/
- NIST SSDF: https://csrc.nist.gov/projects/ssdf and https://csrc.nist.gov/pubs/sp/800/218/final
- NIST CSF 2.0: https://www.nist.gov/cyberframework
- NIST SP 800-61 Rev. 3: https://csrc.nist.gov/pubs/sp/800/61/r3/final
- NIST OSCAL: https://csrc.nist.gov/Projects/Open-Security-Controls-Assessment-Language
- SARIF 2.1.0: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
- CycloneDX specification/version: https://cyclonedx.org/specification/overview/
- SPDX: https://spdx.github.io/spdx-spec/
- OpenSSF Scorecard: https://scorecard.dev/
- SLSA: https://slsa.dev/spec/v1.0/
- OWASP LLM Top 10 2026 announcement: https://genai.owasp.org/2026/09/01/owasp-genai-security-project-unveils-2026-top-10-for-llm-applications-new-agent-control-standard-and-sponsors-as-community-tops-30000-members/
- OWASP Agent Control Standard: https://genai.owasp.org/resource/agent-control-standard-acs/
- OWASP Top 10 for Agentic Applications announcement: https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/

The exact content identifiers and machine-readable mapping format for these 2026 AI resources remain to be pinned during v2 research. Their inclusion in this baseline is not authorization to implement AI capabilities.
