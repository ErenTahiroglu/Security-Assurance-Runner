# Findings and evidence contract

**Status:** ARCHITECTURAL PROPOSAL for a versioned contract, not an implementation.

A finding record should contain schema version; stable record identifier; run ID; repository canonical identity and commit SHA; tool name/version/digest; rule identifier; native and normalized severity; confidence with source; message; location; first/last seen if known; lifecycle/disposition; source artifact digest/reference; and provenance. Unknown values remain unknown. Do not derive exploitability or confirmed vulnerability solely from scanner output.

Execution receipt should bind run ID, plan/policy digests, mode, source identity, authorization reference, start/end, tool/database identity and freshness, expected/actual checks, exit/error/cancel states, input/output digests, and declared coverage/limitations. Distinguish source-declared metadata from machine-observed facts, independent review, and owner-authorized disposition.

Preserve original report bytes or a controlled immutable reference and digest when permitted. Parse untrusted reports with bounded size/depth, strict schemas, no implicit URL fetching or entity expansion, and safe path handling. Reports should minimize source excerpts and secrets.

**Format assessment:** SARIF 2.1.0 is a candidate for static-analysis results; it is not a complete run authorization, coverage, or policy contract. CycloneDX is a strong SBOM/supply-chain candidate; do not assume it models all findings and run evidence. OSCAL can represent controls, assessments and plans in machine-readable forms, but may be more than v1 requires. Consider a small SAR-specific versioned envelope with optional standards-based payloads. No format is selected.

**REQUIRED FUTURE TEST:** malformed reports, determinism, round-trip stability, identity binding, digest mismatch, schema evolution, secret minimization, and consistent unknown/error behavior.
