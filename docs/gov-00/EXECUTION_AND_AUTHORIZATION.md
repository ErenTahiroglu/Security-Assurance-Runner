# Execution and authorization model

**OWNER-APPROVED REQUIREMENT:** Three explicitly selected modes: `CI`, `LOCAL`, `HYBRID`. Mode changes the authorized execution location, never the policy strength.

**ARCHITECTURAL PROPOSAL:** Each run binds immutable candidate identity, selected checks, allowed categories, targets, resource budgets, tool identities, policy version and authorization evidence. Default scope is source-only. Active DAST/fuzz actions require explicit target authorization. Configuration cannot make arbitrary shell text trusted.

## Authority and trusted inputs

| Decision | Permitted authority (proposed) | Untrusted input cannot do |
|---|---|---|
| Define security policy and required checks | Source of truth is a policy bundle/version bound to an exact SAR baseline commit explicitly authorized by the repository owner. The authority record names canonical repository ID, commit, policy path/version/digest and approval. Changes require a separate designated reviewer and explicit owner/delegate approval for the exact version | Supply or weaken policy, remove mandatory checks, choose a more permissive fallback, or self-assert approval |
| Request a run | CI integration or operator may request a run | Establish trust, redefine expected checks, or convert a request into target authorization |
| Authorize active targets | Target owner or explicitly delegated authorizer for the exact canonical target set, test categories, constraints and expiry | Authorize unspecified hosts, broaden a target by redirect, or infer authorization from mere possession of a URL |
| Grant a finding exception | Designated security reviewer/owner-authorized delegate, distinct from the requester where practicable, for exact finding(s), repository/commit, reason and expiry | Waive a required test, evidence requirement, target authorization, or another finding |
| Approve stable release | Repository owner after independent review of the exact candidate SHA, actual relevant validation, residual-risk record and owner disposition | Treat a green workflow, digest, maintainer claim, or policy PASS as release authorization |

**Trust precedence proposal:** an owner-approved policy version and its required-check set govern a run. The run request may select only a policy-permitted profile and may narrow scope; it cannot relax mandatory requirements. Conflicting, missing, expired, or unrecognized policy or authority evidence means refuse the affected action and report `INDETERMINATE`; never fall back to operator-supplied policy. The operator-supplied plan, policy text, digest, target selector and claimed approvals are data, not trust anchors. A matching SHA-256 digest establishes byte integrity relative to that supplied value; it does not establish who approved the bytes or whether they are authoritative.

**Current implication:** SAR `main` is only an unaccepted bootstrap and contains no trusted runtime policy baseline. A policy change on `development` is a proposal until its exact baseline/version is owner-authorized. No policy can be trusted merely because it is committed to an unprotected branch.

**UNRESOLVED DECISION:** The mechanism that authenticates the owner approval record and policy authority record, reviewer delegation rules, and proof of target-owner authority. Until a future milestone specifies and tests those mechanisms, the proposed model is not enforceable and no result can claim trusted-policy PASS.

**Synthetic adversarial example:** A run request supplies a policy that omits SCA and includes the matching SHA-256 digest, plus a field saying `approved_by=owner`. The digest and field are untrusted claims; SAR must not treat them as policy approval. If no separately trusted approved policy and authorization can be resolved, refuse or report `INDETERMINATE`, and do not start active testing.

| Mode | Proposed meaning | Security invariants |
|---|---|---|
| CI | Run on a declared CI worker | Bind provider repository identity, exact SHA, event/run/attempt and each expected stage; active scope still needs separate authorization |
| LOCAL | Run on the operator’s workstation | Bind the same policy/plan/repository identity; requester identity is not target-owner authority; record local limits |
| HYBRID | Stages execute across local/CI contexts | Every stage must bind the identical immutable parent plan, trusted policy, repository/commit and stage-specific scope; reconcile all expected stages |

## Cross-mode run and stage binding

**ARCHITECTURAL PROPOSAL:** Before execution, a trusted run plan binds: canonical repository identity (including provider numeric ID when applicable) and exact full commit SHA; immutable plan ID and canonical plan digest; trusted policy source, version, authority record and digest; selected mode; complete expected scanner/check set and mandatory/optional classification; exact stage IDs and roles; permitted test categories; exact authorized targets and authorization principal/scope/expiry for active testing; tool identities/versions; and resource/time limits. Hashes are integrity identifiers only; they do not authenticate the plan, policy, requester, or authorizer.

Each stage receipt binds the parent run and plan IDs/digest, repository identity and commit, policy version/digest, unique stage ID and attempt, mode/location, expected and observed scanner identities, target/category authorization reference where active, start/end and authorization expiry, execution/coverage status, and every produced artifact digest and media type. Stage output is untrusted until parsed and checked against that binding.

An active stage may start only while its exact target/category authorization is valid. If that authorization expires before the stage completes, the proposed behavior is to stop/cancel the active stage and record it incomplete; a late result cannot satisfy the required stage.

Reconciliation may call a run complete only when every policy-mandatory stage is present, current, valid, and agrees on all bound identities and scopes. A missing stage, mismatched commit/policy/plan, expired scope, duplicate conflicting stage, unrecognized attempt, malformed receipt, or missing artifact makes reconciliation incomplete and policy `INDETERMINATE` (or `BLOCK` when a known blocking finding already exists). Do not combine a local result from another commit or policy with a CI result. HYBRID is a location plan, not permission to merge unrelated evidence.

**REQUIRED FUTURE TEST:** Substitute a stage from another repository, commit, policy, run, stage attempt, or expired target authorization; omit a mandatory stage; provide conflicting duplicate receipts; and substitute an artifact with a different digest. Each must prevent a complete/PASS result. Actual CI identity, target authorization and network enforcement mechanisms remain unimplemented and unresolved.

A run plan should enumerate test categories, source/target scope, authorization principal and expiry, offline status, network policy, process resource/time/output ceilings, cancellation behavior, expected adapters, pinned tool/database versions, and evidence destination. Inability to enforce a boundary means the relevant active test is unsupported or refused, not silently downgraded.

Process launch proposal: fixed executable identity, argument vector, controlled environment, no shell, minimal inherited credentials, per-run scratch, output caps, timeout and process-tree cancellation. Tool output and reports are hostile input. Record failures, cancellation, skipped work, unsupported capabilities and missing evidence separately.

A Docker container alone is not a security proof. Validate daemon/socket exposure, host mounts, privileges, capabilities, kernel, namespace, network, user mapping, secrets and resource limits. Windows/macOS container semantics differ from Linux; document platform-specific guarantees and gaps. No arbitrary user-supplied command is trusted because it is in a SAR config file.

**AI:** no AI calls/data transfer when disabled. v1 contains no provider adapter. Future AI Review is analysis/suggestion-only and cannot write or execute by being enabled. AI Adversarial Testing is a distinct v2 authorization and execution capability against explicit targets with independent result validation and no permission escalation.

**REQUIRED FUTURE TEST:** target allowlist and redirects; DNS rebinding; network egress; shell injection; timeout and child cleanup; archive traversal; non-root process; resource limits; cross-run isolation; mode parity; disabled AI network capture; cancellation and partial evidence.
