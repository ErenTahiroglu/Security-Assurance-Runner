# Technology evaluation

**Status:** ARCHITECTURAL PROPOSAL; choices require GOV-01 evidence and independent review.

| Option | Strengths | Risks / costs | Current disposition |
|---|---|---|---|
| Rust-centered CLI | Memory safety; small deployable binary; aligns with ECE experience; strong typed schemas | More effort integrating Python-native scanners; portability and subprocess crates still require review | Preferred candidate, not selected |
| Go-centered CLI | Strong CLI/process/network ecosystem; simple cross-builds; broad operator familiarity | Runtime/dependency and parsing safety still require care; less reuse of owner’s Rust expertise | Viable alternative |
| Python orchestration | Broad security-tool ecosystem; fast adapters and experimentation | Interpreter/runtime packaging; dependency exposure; environment collisions; harder reproducible offline install | Consider for adapters only |
| Hybrid | Isolates core from tool ecosystems; adapters may follow tool-native languages | IPC/versioning and packaging complexity; increases support surface | Defer absent demonstrated need |

**VERIFIED SOURCE FACT:** SARIF 2.1.0 is a standard interchange format for static analysis results. CycloneDX 1.7 is listed as current by its official specification page, published 2025-10-21. NIST describes OSCAL as machine-readable XML, JSON and YAML models for control and assessment information. Each should be evaluated by actual consumer compatibility, not selected by brand.

## Platform considerations

Owner requested macOS ARM64 and Windows x64, with Linux x64 appropriate for isolated execution. Local mode should not falsely represent OS-level isolation. A Linux CI worker may provide a consistent DAST execution host, but job isolation, network egress, ephemeral credentials and runner trust remain deployment assumptions. Windows/macOS may initially support source and static checks with clearly declared isolation limits.

External scanner integrations should pin identity/version, record image/package digest where available, state database/cache age, and separate tool failure from clean findings. AI provider adapters are out of scope until v2.

**UNRESOLVED DECISIONS:** Supported OS minimums; package/signing and update channels; SBOM format; one or multiple result formats; vulnerability database update and offline policy; adapter API compatibility strategy.

**REQUIRED FUTURE TEST:** Reproducible build and clean machine packaging on each supported OS; no-network execution trace; pinned tool identity verification; crash/timeout behavior. No tests executed for GOV-00.
