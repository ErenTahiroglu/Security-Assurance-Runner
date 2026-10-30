# Source provenance

Research snapshot prepared 2026-10-30. Links are sources, not endorsements; mutable pages must be rechecked at implementation time.

## Repositories
- SAR: https://github.com/ErenTahiroglu/Security-Assurance-Runner (REST ID 1439402924; owner ErenTahiroğlu).
- DefectDojo reference commit: https://github.com/DefectDojo/django-DefectDojo/commit/c360df03a9399cbe6b26138bd0289949c27eb732 (verified exact SHA; BSD-3-Clause).
- GUAC reference commit: https://github.com/guacsec/guac/commit/a3f0a4df51abcf271221cf9c400de3158d9c20fa (verified exact SHA; Apache-2.0).
- ECE historical `main` bootstrap: https://github.com/ErenTahiroglu/Evidence-Checkpoint-Engine/tree/bead6837e1ec03c8fe1ac3c8d09fd374fb8b0e02 (rechecked 2026-10-30; README describes documentation-only bootstrap).
- ECE independently accepted GOV-01 offline verifier: https://github.com/ErenTahiroglu/Evidence-Checkpoint-Engine/tree/415990746d5bbd3756f743b4b5a7673b36228567; acceptance and limitations recorded in https://github.com/ErenTahiroglu/Evidence-Checkpoint-Engine/issues/3#issuecomment-6516966400.
- ECE current development observation: https://github.com/ErenTahiroglu/Evidence-Checkpoint-Engine/tree/4cf9f2245f31d04c9c9699d9d1c998b0e658c7e7 (rechecked 2026-10-30). This is six commits beyond the accepted GOV-01 offline verifier SHA. The tree includes a GitHub read-only adapter, tests, workflow, GOV-02 plan and a follow-up correction commit. Issue #4 remains OPEN: https://github.com/ErenTahiroglu/Evidence-Checkpoint-Engine/issues/4. Its independent review requested corrections on the preceding `ccde36586a4df170db38f018d6eb8a8a653de99f`; the current head has not been independently accepted in the evidence checked for this R2 update.
- ECE issue #3 records `GOV_01_INDEPENDENT_REDTEAM_PASS_WITH_LIMITATIONS` for offline verifier SHA `415990746d5bbd3756f743b4b5a7673b36228567`, with explicit limits: no authenticated external GitHub provenance, no production release, no ATM integration or `main` promotion. Source: https://github.com/ErenTahiroglu/Evidence-Checkpoint-Engine/issues/3#issuecomment-6516966400 (rechecked 2026-10-30).
- No accepted stable SAR-facing GitHub adapter contract was established by the current ECE evidence. The accepted offline verifier and later changing development adapter are distinct scopes; recheck exact head, review and issue state before GOV-05.

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
- SLSA specification v1.2: https://slsa.dev/spec/v1.2/
- OWASP LLM Top 10 2026 announcement: https://genai.owasp.org/2026/09/01/owasp-genai-security-project-unveils-2026-top-10-for-llm-applications-new-agent-control-standard-and-sponsors-as-community-tops-30000-members/
- OWASP Agent Control Standard: https://genai.owasp.org/resource/agent-control-standard-acs/
- OWASP Top 10 for Agentic Applications announcement: https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/

The exact content identifiers and machine-readable mapping format for these 2026 AI resources remain to be pinned during v2 research. Their inclusion in this baseline is not authorization to implement AI capabilities.

## GOV-00 R2 trust and policy-authority research

Research checked 2026-10-30. GitHub documentation is continuously updated; the linked pages are the exact official pages consulted and must be rechecked before implementation. No security mechanism in these documents was implemented or experimentally tested in SAR.

| Source | Exact version/status observed | Relevance and limits |
|---|---|---|
| [GitHub available ruleset rules](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets) and [protected branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches) | Official, mutable documentation; retrieved 2026-10-30 | Required status checks can be scoped to an expected GitHub App. Write-capable actors/integrations may otherwise set statuses; ruleset bypass and admin authority remain governance risks. This does not prove the scanner result correct. |
| [GitHub required-check troubleshooting](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks) | Official, mutable documentation; retrieved 2026-10-30 | A conditionally skipped job may report success for dependent jobs; workflow-level path/branch skips have different pending behavior. SAR must reconcile expected and actually executed mandatory jobs rather than infer completeness from a green summary. |
| [GitHub Actions OIDC reference](https://docs.github.com/en/actions/reference/security/oidc) | Official, mutable documentation; retrieved 2026-10-30 | `id-token: write` permits requesting an OIDC token and does not itself grant resource write access. Claims need validation by a relying party with exact audience and identity expectations. Workflow identity is not owner policy approval. |
| [GitHub artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations) | Official, mutable documentation; retrieved 2026-10-30 | Attestations establish build provenance/where and how software was produced. Presence alone does not establish policy approval, complete security testing, or a correct finding. |
| [GitHub deployment environments](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments) | Official, mutable documentation; retrieved 2026-10-30 | Required reviewers can gate a job and access to environment secrets, and self-review prevention is configurable. This is an optional workflow gate, not an independent SAR policy authority or target-owner proof. |
| [GitHub `pull_request_target` security guidance](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target), [GITHUB_TOKEN concept](https://docs.github.com/en/actions/concepts/security/github_token) | Official, mutable documentation; retrieved 2026-10-30 | Privileged workflow handling of untrusted pull-request code can expose credentials; token permissions should be minimal. These are future design constraints, not configured SAR controls. |
| [SLSA v1.2 — Verifying artifacts](https://slsa.dev/spec/v1.2/verifying-artifacts) | SLSA specification v1.2; document states **Approved**; retrieved 2026-10-30 | Verification compares provenance/signature against a preconfigured root of trust and expected repository/build fields. SLSA provenance authenticates build claims within the verifier's trust assumptions; it does not measure scan adequacy. |
| [DSSE protocol repository](https://github.com/secure-systems-lab/dsse/tree/b531b787bb3e5f0c3e1c19cee84da1c5d569b061) | Repository head observed at `b531b787bb3e5f0c3e1c19cee84da1c5d569b061`, commit 2026-10-09; no numbered release version was identified; retrieved 2026-10-30 | DSSE PAE binds payload type and bytes. DSSE does not specify signature algorithms, key authority, enrollment, or revocation. `keyid` is an unauthenticated hint. Considered as a typed-envelope candidate only. |
| [The Update Framework Specification](https://github.com/theupdateframework/specification/blob/e2bc7d83d0740aaae8dd7133dd4f237ce3d86b16/tuf-spec.md) and [metadata roles](https://theupdateframework.io/docs/metadata/) | Official specification source at observed commit `e2bc7d83d0740aaae8dd7133dd4f237ce3d86b16`, `SPEC_VERSION 1.0.37`; latest stable in repository when checked 2026-10-30 | Root/delegated roles, versioned signed metadata, expiry and rollback/freeze defenses inform the proposal. SAR does not select or implement the full TUF update framework and cannot claim its guarantees. |
| [RFC 8032 — EdDSA](https://datatracker.ietf.org/doc/html/rfc8032) | IETF RFC 8032, January 2017; retrieved 2026-10-30 | Ed25519/Ed448 signature algorithm specification (informational, not Internet Standards Track). No algorithm or implementation library is selected for SAR; future work must use maintained cryptographic APIs, not custom cryptography. |
| [RustCrypto `ed25519-dalek` verification API](https://docs.rs/ed25519-dalek/3.0.0/ed25519_dalek/struct.VerifyingKey.html) | `ed25519-dalek` 3.0.0 docs observed 2026-10-30 | `VerifyingKey::verify_strict` is one Rust API candidate for a future RFC 8032 Ed25519 verification path. It is a crate API, not a format or owner-trust standard; dependency maintenance, audit, feature configuration, key encoding and compatibility require later review. Not selected or installed. |
| [Sigstore security model](https://docs.sigstore.dev/about/security/), [Cosign signature verification](https://docs.sigstore.dev/cosign/verifying/verify/) | Official current documentation; retrieved 2026-10-30; no versioned standard identified on the pages | Keyless identity/certificate/transparency-log workflow can provide artifact/workflow provenance if issuer and identity are checked. It relies on its OIDC and Sigstore trust roots and does not independently establish SAR owner policy authority or scan correctness; not selected as SAR's root. |

**R2 conclusion from these sources:** a verifiable signature needs a verifier-configured trust root and explicit expectations. Provenance, branch protection and signatures each answer different questions. The R2 architecture is a proposal; owner enrollment, key custody, trusted freshness, executable integrity, and all implementation choices remain open.
