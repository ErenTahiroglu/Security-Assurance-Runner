# GOV-00 — architecture and scope

**Status:** ARCHITECTURAL PROPOSAL, pending independent review. No implementation or validation claim.

## Purpose and constraints

**OWNER-APPROVED REQUIREMENT:** Orchestrate selected security tools; normalize and interpret findings; evaluate evidence-aware policy. Do not recreate a full scanner, DefectDojo, or GUAC. v1/v2 boundary and three explicit execution modes are defined in the charter and execution model.

**ARCHITECTURAL PROPOSAL:** A modular monolith with a small CLI, versioned run manifest, narrow adapters, canonical finding/evidence schema, policy evaluator, and report/export layer. Keep adapters isolated behind versioned inputs/outputs. No database or GUI for v1. Prefer local files and deterministic schemas initially. External tools are invoked as separately identified processes; their output is untrusted input.

## Language recommendation

**PROPOSED:** Rust core/CLI, with external scanner adapters consuming and producing documented interchange formats. Rust is aligned with owner’s ECE experience and offers strong memory-safety properties and static distribution. This is not permission to begin GOV-01.

- Rust: strong safety and single-binary distribution; scanner ecosystems and orchestration ergonomics can require adapters.
- Go: mature CLI/concurrency and easy distribution; garbage-collected runtime and weaker alignment with ECE.
- Python: broad security-tool ecosystem and fast adapter authoring; runtime/dependency distribution and interpreter environment complexity.
- Hybrid: Rust policy/core with separately versioned adapters can isolate ecosystems but increases IPC, packaging, compatibility and support costs. Do not adopt by default without measured need.

**UNRESOLVED DECISION:** Confirm language after a GOV-01 prototype compares macOS ARM64, Windows x64 and Linux x64 packaging, offline operation, process supervision and dependency footprint. Cross-platform container isolation is not uniform; Linux-hosted isolated DAST may be the supportable initial boundary.

## Layer proposal

1. Manifest and authorization parser: bind run to repository, commit, scope, targets, categories, mode, limits and policy digest.
2. Scheduler: fixed adapters, explicit resource and timeout limits, cancellation and per-run scratch isolation.
3. Adapters: pinned tool identity/version, argument arrays, no shell interpolation, bounded outputs.
4. Normalization: schema-validated untrusted outputs into SAR records, preserving original artifact digests and source claims.
5. Policy: evaluate findings separately from execution completeness, coverage, exceptions and verification status.
6. Export: human report plus versioned machine evidence. No claim of completeness or compliance from a successful process exit alone.

## Scope by version

v1 includes SAST, SCA, secrets/configuration, supply-chain evaluation, authorized isolated DAST and fuzzing, standards mapping, auditable findings, risk-based CI policy and evidence export. v2 alone includes AI review and authorized adversarial AI-agent testing. Default operation has no AI. Details: [roadmap](ROADMAP_AND_ACCEPTANCE_GATES.md).

## Status register

- **VERIFIED SOURCE FACT:** SARIF 2.1.0, CycloneDX and OSCAL are extant interoperability specifications; their existence does not establish fit or implementation.
- **ARCHITECTURAL PROPOSAL:** Modular monolith, Rust-first evaluation, file-backed evidence, schema-versioned adapters.
- **UNRESOLVED DECISION:** definitive language, packaging, policy syntax, local cache format, minimum supported OS versions, and which export format is normative.
- **REQUIRED FUTURE TEST:** cross-platform clean-room packaging; malformed report handling; deterministic reruns; offline database freshness labeling; and resource/cancellation behavior.
- **IMPLEMENTED/TESTED FACT:** None in GOV-00.
