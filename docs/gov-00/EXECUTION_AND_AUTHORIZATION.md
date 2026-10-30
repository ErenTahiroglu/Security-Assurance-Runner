# Execution and authorization model

**OWNER-APPROVED REQUIREMENT:** Three explicitly selected modes: `CI`, `LOCAL`, `HYBRID`. Mode changes the authorized execution location, never the policy strength.

**ARCHITECTURAL PROPOSAL:** Each run binds immutable candidate identity, selected checks, allowed categories, targets, resource budgets, tool identities, policy version and authorization evidence. Default scope is source-only. Active DAST/fuzz actions require explicit target authorization. Configuration cannot make arbitrary shell text trusted.

| Mode | Proposed meaning | Security invariants |
|---|---|---|
| CI | Run on a declared CI worker | Candidate SHA/event freshness, least-privilege token, ephemeral workspace, egress denial except explicit target |
| LOCAL | Run on the operator’s workstation | Visible confirmation for active targets; report local limits; do not infer container safety |
| HYBRID | Static/local preparation plus bounded CI active tests or vice versa | Explicit stage ownership, shared run identity, preserve incomplete status across stages |

A run plan should enumerate test categories, source/target scope, authorization principal and expiry, offline status, network policy, process resource/time/output ceilings, cancellation behavior, expected adapters, pinned tool/database versions, and evidence destination. Inability to enforce a boundary means the relevant active test is unsupported or refused, not silently downgraded.

Process launch proposal: fixed executable identity, argument vector, controlled environment, no shell, minimal inherited credentials, per-run scratch, output caps, timeout and process-tree cancellation. Tool output and reports are hostile input. Record failures, cancellation, skipped work, unsupported capabilities and missing evidence separately.

A Docker container alone is not a security proof. Validate daemon/socket exposure, host mounts, privileges, capabilities, kernel, namespace, network, user mapping, secrets and resource limits. Windows/macOS container semantics differ from Linux; document platform-specific guarantees and gaps. No arbitrary user-supplied command is trusted because it is in a SAR config file.

**AI:** no AI calls/data transfer when disabled. v1 contains no provider adapter. Future AI Review is analysis/suggestion-only and cannot write or execute by being enabled. AI Adversarial Testing is a distinct v2 authorization and execution capability against explicit targets with independent result validation and no permission escalation.

**REQUIRED FUTURE TEST:** target allowlist and redirects; DNS rebinding; network egress; shell injection; timeout and child cleanup; archive traversal; non-root process; resource limits; cross-run isolation; mode parity; disabled AI network capture; cancellation and partial evidence.
