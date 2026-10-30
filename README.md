# Security-Assurance-Runner (SAR)

**Owner:** Eren Tahiroğlu
**Status:** GOV-01 NONPRODUCTION PROTOTYPE — NOT A WORKING SECURITY SCANNER, NOT AN INDEPENDENTLY VALIDATED SECURITY PRODUCT.

SAR is a planned system for orchestrating security tools, normalizing findings, and evaluating evidence-aware policy. It is publicly source-available under PolyForm Noncommercial License 1.0.0, not OSI-approved open-source software. This prototype inspects bounded manifests and tests synthetic trust and report reconciliation. It does not implement scanning, operational policy authorization, AI, or independent evidence verification.

Run `cargo run --locked -- version` for the version. The `inspect` command reads a manifest on stdin and refuses evaluation because no operational root enrollment exists. Details, status codes and limitations are in the [GOV-01 report](docs/gov-01/GOV_01_IMPLEMENTATION_REPORT.md).

Proposed v1: SAST, SCA, secret/configuration and supply-chain assessment, authorized isolated DAST and fuzzing, control mapping, auditable reporting, CI policy, CI/LOCAL/HYBRID modes, evidence export. Proposed v2 adds opt-in AI review and separately authorized AI-agent adversarial testing. AI is off by default.

## Documentation
- [Project charter](docs/PROJECT_CHARTER.md)
- [Branch governance](docs/BRANCH_GOVERNANCE.md)
- [GOV-00 architecture package](docs/gov-00/ARCHITECTURE_AND_SCOPE.md)
- [Third-party register](docs/THIRD_PARTY_CODE_REGISTER.md)
- [Source provenance](docs/SOURCE_PROVENANCE.md)
- [Red Team handoff](docs/gov-00/INDEPENDENT_REDTEAM_HANDOFF.md)
- [Security reporting](SECURITY.md)

GOV-00 R2 architecture was accepted for documentation scope; GOV-01 awaits independent review and owner disposition.
