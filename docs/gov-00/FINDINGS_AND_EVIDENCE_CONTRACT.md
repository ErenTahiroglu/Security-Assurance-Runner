# Findings and evidence contract

**Status:** ARCHITECTURAL PROPOSAL for a versioned contract, not an implementation.

A finding record should contain schema version; stable record identifier; run ID; repository canonical identity and commit SHA; tool name/version/digest; rule identifier; native and normalized severity; confidence with source; message; location; first/last seen if known; lifecycle/disposition; source artifact digest/reference; and provenance. Unknown values remain unknown. Do not derive exploitability or confirmed vulnerability solely from scanner output.

Execution receipt should bind run ID, immutable plan ID/digest, trusted policy authority/version/digest, mode, source identity, authorization references, stage IDs/attempts, start/end, tool/database identity and freshness, expected checks classified mandatory/optional, actual check results, exit/error/cancel states, input/output artifact digests/media types, and declared coverage/limitations. A digest does not authenticate the policy or authorize a run. Distinguish source-declared metadata from machine-observed facts, independent review, and owner-authorized disposition.

**PROPOSED CONTRACT STATUS:** Finding severity, scanner execution, coverage, policy decision, independent verification, and human authorization are separate dimensions. A zero-finding scan is only a successful tool result. PASS requires every mandatory check and required coverage condition in the trusted policy to be satisfied. A missing/skipped/failed/cancelled/unsupported check, malformed or truncated required report, stale required vulnerability database, identity conflict, or incomplete required target coverage cannot become PASS. A valid known blocking finding yields BLOCK; otherwise unresolved mandatory evidence yields INDETERMINATE. Exceptions are separately authorized and scoped to exact findings; they do not satisfy execution requirements.

For CI, LOCAL and HYBRID reconciliation, each stage must bind the identical parent plan, trusted policy, repository identity and exact commit; its own stage/attempt; authorized target and category (for active tests); expiry; expected scanner set; and artifact digests. Missing, stale, mismatched, duplicated-conflicting or malformed stage receipts make the combined evidence incomplete. See [execution and authorization](EXECUTION_AND_AUTHORIZATION.md) and [policy semantics](SECURITY_POLICY_MODEL.md).

Preserve original report bytes or a controlled immutable reference and digest when permitted. Parse untrusted reports with bounded size/depth, strict schemas, no implicit URL fetching or entity expansion, and safe path handling. Reports should minimize source excerpts and secrets.

**Format assessment:** SARIF 2.1.0 is a candidate for static-analysis results; it is not a complete run authorization, coverage, or policy contract. CycloneDX is a strong SBOM/supply-chain candidate; do not assume it models all findings and run evidence. OSCAL can represent controls, assessments and plans in machine-readable forms, but may be more than v1 requires. Consider a small SAR-specific versioned envelope with optional standards-based payloads. No format is selected.

**REQUIRED FUTURE TEST:** malformed reports, determinism, round-trip stability, identity binding, digest mismatch, schema evolution, secret minimization, and consistent unknown/error behavior.
