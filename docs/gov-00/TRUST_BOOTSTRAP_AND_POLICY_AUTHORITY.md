# Trust bootstrap and policy authority

**Status:** ARCHITECTURAL PROPOSAL for GOV-00 R2. No cryptographic, policy-verification, CI-ingestion, or security-testing control is implemented. This proposal is not owner-approved and does not authorize GOV-01.

**Owner-approved constraints:** SAR must not treat a digest, mutable project file, Git commit, GitHub login, workflow execution, AI output, or self-declared approval as independent authorization. A trusted policy is required before a security result can be PASS. Active testing needs separate, exact target authorization. `main` promotion needs a separate owner decision after independent review.

## Decision summary

**PROPOSED:** Use a small, independently enrolled owner verification root (Option C) to authenticate purpose-bound policy and authorization records. Use GitHub rulesets, status checks, OIDC and artifact attestations as supplementary CI identity and execution evidence. Keep an OS-managed local copy of public trust material for offline verification (Option B as a storage/availability feature, not as its own authority). Do not treat GitHub-native repository state alone (Option A) as owner approval.

Initial v1 authority is the repository owner directly. Add narrowly scoped delegated issuers only if a concrete operating need justifies them. The owner establishes the initial public-key fingerprint through an independently authenticated channel; the public key and policy bytes may then be distributed by ordinary means and verified against that pre-enrolled anchor. No custom certificate authority, hosted signer, KMS, HSM service, or full TUF deployment is proposed. A standard signed-envelope format such as DSSE is a candidate, not selected or implemented.

**UNRESOLVED OWNER DECISION:** Approve or reject Option C; choose the independent fingerprint-verification channel and initial key custody; decide whether v1 is owner-only or needs explicit delegation; set policy and authorization validity limits; and select the eventual signature algorithm/library and trust-store update procedure. Until those decisions and implementation tests exist, SAR cannot claim an authenticated security-policy PASS or authorize active testing.

## Trust domains and terms

These are separate questions, even if a later deployment uses one tool to check more than one of them:

1. **SAR executable integrity:** Is this exact runner binary/source build trusted to evaluate inputs honestly? A valid policy signature cannot make a compromised executable trustworthy.
2. **Trust-root integrity:** Which owner-established verification key or root metadata authorizes policy issuers for this installation and project?
3. **Policy approval:** Did an issuer authorized by that root approve these exact policy bytes and check requirements for this exact repository scope?
4. **Run request:** Who asked SAR to evaluate a particular commit in a particular mode? The request does not grant policy-writing or active-target authority.
5. **Active-target authorization:** Did the owner or authorized controller of each exact external target permit these specific active test categories for this bounded time and scope?
6. **Execution and evidence:** Which trusted execution context ran which expected checks and produced which artifacts for the exact commit, plan, and attempt?
7. **Exception and release decisions:** Was a finding exception narrowly approved? Did the repository owner separately authorize promotion of an exact candidate to stable `main`?

**Cryptographic integrity is not authority.** A SHA-256 digest shows that bytes match a supplied digest. A signature verifies only against a public key that was already trusted for the relevant purpose and scope. A key supplied beside its own signature in an untrusted manifest is not a trust bootstrap. A Git commit or GitHub identity is not, by itself, proof that the owner approved a policy.

## Architecture alternatives

| Option | Strengths | Limits and failure cases | Proposed disposition |
|---|---|---|---|
| **A — GitHub-native policy authority**: protected repository/ref, rulesets, selected required-check source, and verified GitHub API/run context | Fits CI; repository ID, commit, workflow and run context can be inspected; rulesets can constrain merges and identify an expected GitHub App for a status check | Repository administrators and owners retain powerful authority and possible bypass; policies/workflows can change in the same repository; required-check configuration can be absent or misconfigured; a status source proves who reported a check, not that its policy was owner-approved or its scan adequate. Local/offline use cannot independently query current GitHub state. OIDC authenticates a workflow context only to a relying party that verifies expected issuer/audience/claims; it does not make a workflow an owner policy issuer. | **Reject as the sole policy root.** Retain as supplementary CI execution and governance evidence after separate owner configuration. Branch/ruleset enforcement is currently absent; see #10. |
| **B — locally pinned policy authority**: operator-installed trust material and policy outside the scanned tree | Small and usable offline; avoids trusting repository-local policy files; simple for a single operator | Same-user malware or a compromised runner can alter local files or outputs; machine migration, backup restoration and policy updates can silently roll back; operator enrollment is not automatically owner approval; difficult to distribute consistently in CI; local storage protects against adjacent repository edits only to the extent the host and account remain trustworthy. | **Use only as the local trust-material cache/anchor store after independent enrollment.** It is not sufficient as the independent authority by itself. |
| **C — independently enrolled verification root and purpose-bound signed records** | A project cannot replace the root by changing its own manifest; one authority can explicitly bind target repo, policy digest, purpose, roles and time; supports CI, local and hybrid checks of the same signed material; public verification can work offline | Requires a deliberate initial enrollment and careful private-key custody; key compromise, stale revocation state, untrusted clocks and compromised runner remain material; a signature alone does not prove scan correctness. | **Recommend as the smallest design that addresses the bootstrap requirement**, with the owner as initial root/issuer and GitHub as supplementary CI evidence. This remains a proposal pending owner decision. |

No option proves the SAR executable is honest on a compromised host. No model can know about a revocation that it has not received. Cryptographic verification does not replace reviewer judgment or target-owner consent.

## Trust bootstrap and policy lifecycle

### Initial enrollment

1. The repository owner establishes the root and owns the initial authorization decision. Initial v1 policy approval is owner-only unless the owner later authorizes a specific scoped delegate.
   - **Proposed key isolation:** keep the root private key in owner-controlled offline custody and use it outside SAR, CI workflows, scanned source trees, repository secrets, operator manifests and AI processes. The initial design can use that owner-controlled process directly for policy approvals; a separate delegated policy key is added only if needed and is authorized by the root. No key-generation method, device, or custody service is selected here.
2. Before any SAR project policy is accepted, the installation receives the public verification material and expected root fingerprint through an owner-designated channel independent of the scanned repository and the policy bundle. The operator compares the complete fingerprint with a second independently authenticated owner communication or other owner-approved out-of-band reference. Merely downloading both key and fingerprint from the same mutable repo, branch, workflow artifact, or manifest is not independent verification.
3. The owner-selected enrollment process records the root key identity/fingerprint, permitted purposes, target repository IDs, key validity interval, root sequence/version, revocation/update reference, and enrollment provenance in a trust store outside the target checkout. An ordinary per-user configuration directory with restrictive host permissions is a possible location, not a security boundary against malware running as that user. Verification checks both key validity and the signed statement's own validity interval.
4. A newly installed SAR receives the anchor only after this explicit enrollment. No trust-on-first-use, silent key discovery, or fallback to a project-supplied key is allowed. The SAR executable and its distribution provenance must be checked separately; the same channel and threat assumptions must be documented.
5. A missing, invalid, ambiguous, or unrecognized trust anchor causes `REFUSED` before a trusted evaluation starts. It cannot be repaired by accepting a project file, a matching digest, a branch commit, an AI recommendation, or an operator's `approved=true` field.

The fingerprint channel and SAR executable verification procedure are **UNRESOLVED OWNER DECISIONS**. A future installer must not claim independent enrollment until those exact steps are documented and tested. An independently maintained verification component could reduce runner self-trust, but adding or using one requires its own owner-approved trust root and is not assumed here.

### Policy approval and applicability

The owner (or a delegate whose authority is itself authenticated by the enrolled root) approves the exact policy byte digest. The signed approval names the canonical provider repository identity and stable repository ID. A Git branch/ref is not the authority boundary. For a GitHub-bound policy, the run still binds to the exact full commit SHA observed for that repository.

Two application models were considered:

- **Per-commit approval:** issue a distinct approval for every source commit. This gives narrow approval scope, but makes ordinary CI use expensive and does not solve whether the runner or test result is trustworthy.
- **Bounded policy applicability (recommended):** one owner-approved policy applies to any commit evaluated for a named repository ID while the policy sequence is current and its signed validity interval has not expired. Each run request and execution receipt still bind the exact full source commit, plan, mode, expected checks, and stage identity. A policy update requires a higher sequence and a newly authenticated approval. No moving branch name substitutes for the commit SHA.

This policy applicability is not a claim that each commit is safe. It defines which mandatory checks must be applied to that commit. Exact release authorization remains per candidate SHA. The owner must choose the maximum policy validity interval and whether a specific policy requires tighter commit or ref scope.

### Policy update, rollback, and root change

- Every approved policy has a strictly increasing sequence within its repository/policy identity. Persist the highest accepted sequence and root version outside the checkout. Reject a lower sequence even if its signature remains cryptographically valid.
- A policy issuer key is authorized only by the enrolled root and only for the purposes, repository IDs, and validity interval in its authenticated delegation. Initial delegation is disabled by default. No delegate may create another delegate unless the root expressly permits that capability.
- Reject signatures whose signing key/delegation is outside its authenticated validity interval, expired or revoked. A signed `issued_at` field is a claim bound to the payload, not independent proof of when signing occurred; evaluating time limits still assumes a sufficiently trustworthy clock or an independently trusted timestamp source.
- A normal uncompromised root rotation uses a root-authorized transition that identifies the new root and monotonically higher root version; the new material is checked against both the current trust state and the separately verified new fingerprint. If the old root is suspected compromised or cannot authenticate a transition, stop and require out-of-band owner re-enrollment. A compromised old key cannot be trusted to revoke itself.
- Revocation or replacement is represented by a newer authenticated root/policy state. When a runner learns that an issuer or policy was revoked during a run, it must cancel affected active work where feasible and prevent that run from yielding PASS. Preserve independently valid positive findings for review; otherwise classify policy outcome as INDETERMINATE and execution as INCOMPLETE where stages did not complete.
- Restoring an older backup can restore an older sequence floor. A host-local sequence floor cannot prove freshness after rollback of the whole host or its storage. An online check against the owner-designated current metadata source or a separately trusted monotonic store could improve freshness; that source and mechanism are unresolved. Do not implement a custom update service or claim TUF-grade guarantees in GOV-00.

## Minimal authorization-record contract

**PROPOSED:** A versioned typed signed envelope, with a DSSE-style payload-type binding as one candidate. The envelope signature must cover both payload type and payload bytes. The payload type identifies the exact schema and purpose; a valid signature for one purpose must not be accepted for another. DSSE does not choose the cryptographic algorithm, establish the key's authority, or provide a revocation service. Its `keyid`, if present, is an unauthenticated lookup hint and never proof of issuer identity. Verification must use keys already enrolled for the required purpose. See the source register for DSSE and TUF references.

The policy approval payload should contain, at minimum:

| Field | Required meaning |
|---|---|
| `schema_version`, `statement_type` | Exact supported schema and purpose, such as `sar.policy-approval.v1`; unknown types fail closed. |
| `target_repository` | Provider, stable repository ID, and canonical repository name/URI. For v1 GitHub use the numeric repository ID as the authority binding; names/URLs are corroborating display fields. |
| `source_applicability` | Explicit bounded rule; proposed default is all exact commits evaluated within the named repository ID during the approval validity interval. The run receipt records the actual full commit SHA. |
| `policy_id`, `policy_digest`, `policy_version`, `policy_sequence` | Stable policy identity; SHA-256 over exact policy bytes; readable version and monotonic sequence. Hash is content identity, not approval. |
| `mandatory_checks`, `optional_checks`, `required_coverage` | Complete check inventory, stable check IDs, required inputs/coverage and freshness constraints; an omitted check is not implicitly optional. |
| `allowed_modes`, `allowed_categories`, `execution_constraints` | Explicit `CI`, `LOCAL`, and/or `HYBRID` modes; permitted source-only or active categories and defined resource/scope restrictions. Active categories still require a separate target authorization. |
| `issuer_key_reference`, `issuer_role` | Claimed issuer identity/role, which the verifier must resolve against the enrolled root or authorized delegation. Payload claims alone are not authority. |
| `issued_at`, `not_before`, `expires_at` | Validity bounds interpreted with a stated trusted-clock assumption. Expired or not-yet-valid records are rejected. |
| `approval_reference` | Human-readable review/approval record identifier or URL for audit. The reference is not itself the approval proof. |
| `delegation_constraints` | For delegated issuers: parent delegation, exact purpose, repository IDs, permitted policy sequence/range, expiry, and whether subdelegation is forbidden. |

Hash the exact policy bytes, reject duplicate JSON keys and ambiguous encodings, and verify the typed signature before using parsed fields. Do not require an unspecified canonical JSON scheme merely to verify a signature over original bytes. A future format must document its byte encoding, strict parser, schema evolution, digest algorithm and signature API before implementation.

Signed approval payloads (policy, target, exception, release, and delegation) use common fields: `schema_version`, exact `statement_type`, `issuer_key_reference` resolved only through enrolled authority, `issued_at`, `not_before`, `expires_at`, `approval_reference`, and a unique statement ID. The signed envelope is verified over the original typed payload bytes. Its envelope key hint never grants authority. A run request uses the same versioned purpose discipline and binds authenticated requester/workflow context; a caller signature, if used, authenticates the requester only and does not turn the request into owner approval. Purpose-specific payloads add:

| Statement purpose | Required purpose-specific fields |
|---|---|
| `sar.run-request.v1` | Authenticated requester/workflow context; repository ID and exact full source commit; selected trusted policy ID/digest/sequence; mode; requested profile/categories; immutable run/plan ID; request time and unique nonce. This is a request record, not an owner-signed approval; requester authentication cannot expand policy. |
| `sar.active-target-authorization.v1` | Target-owner/authorizer identity and role; target ownership/control proof reference; exact canonical host/service/IP and ports; allowed test categories; explicit exclusions/redirect policy; validity interval; resource/rate constraints; applicable repository, run or policy scope; delegation reference if used. No wildcard scope by default. |
| `sar.finding-exception.v1` | Authorized reviewer identity/role; repository ID and exact commit; policy ID/sequence; stable finding ID or narrow rule/location fingerprint; reason; issue/reference; expiry. It cannot waive mandatory checks, required coverage, freshness, active-target authorization or release review. |
| `sar.release-authorization.v1` | Repository ID and exact candidate commit SHA; independent review reference for that exact SHA; actual validation evidence references; residual-risk record digest/reference; owner identity/role; one-time promotion purpose and approval time. It grants no authority to a later SHA. |
| `sar.issuer-delegation.v1` | Parent root/issuer; delegate key identity; exact role and purposes; allowed repository IDs; permitted policy sequence/scope; start/expiry; revocation/version reference; explicit `may_delegate` false by default. |

An authenticated run-request context may be established by local operator attribution or verified CI OIDC/API identity, but neither becomes a policy approval signature. Target ownership proof is unresolved and must be independently checked before the target record can authorize active work. Every signed statement is rejected if its key lacks the exact purpose/role, repository, sequence or time authority.

### Signature algorithm and API

**PROPOSED:** Use a fixed, explicitly allowed signature algorithm and a maintained cryptographic library's verification API; never implement cryptographic primitives or algorithm negotiation in SAR. Ed25519 as specified by RFC 8032 is a candidate for evaluation, and RustCrypto `ed25519-dalek` 3.0.0 documents a `VerifyingKey::verify_strict` API. This is research input only: RFC 8032 is informational rather than an Internet Standards Track RFC, and the crate API is not itself an approval, envelope, key-custody, or revocation standard. GOV-01 must review current maintenance/security status, dependency provenance, implementation configuration, test vectors, algorithm policy and key format before selecting any library or algorithm. No package was installed or selected in R2.

### Distinct authorization statement types

| Statement | Who may approve | What it authorizes | Explicitly does not authorize |
|---|---|---|---|
| **Policy approval** | Owner/root or narrowly delegated policy issuer | Exact policy bytes/check inventory for named repository IDs and validity scope | A particular run, external target test, finding exception, or release |
| **Run request** | Authenticated operator or verified workflow context | Request an allowed evaluation of one exact repository/commit under an already trusted policy and permitted mode | Policy edits, omission of mandatory checks, target ownership, exception, or release |
| **Active target authorization** | Target owner/controller or its explicitly authorized delegate | Exact host/service identifiers, test categories, time window, and constraints for active testing | Other hosts, redirects, broad domains not listed, source policy edits, or release |
| **Finding exception** | Security reviewer authorized for exceptions; separate from requester where practicable | Treatment of exact finding identity/selector for exact repository and commit, with reason and expiry | Any required check, coverage, evidence freshness, other finding, target authorization, or release |
| **Stable release authorization** | Repository owner after independent review | Promotion of exact candidate SHA after actual relevant validation and residual-risk disposition | Future commits or a general policy PASS as release permission |

Records are purpose-separated and typed. A source-only policy or run request is never a DAST authorization. A finding exception cannot make a skipped required check complete. A policy PASS is not an owner release decision.

## Authority and verification matrix

All authority below is **proposed**. Authentication proof unavailable or invalid means the affected approval cannot be accepted. The runner does not infer role from a username string, repository write access, workflow execution, AI output, or possession of a manifest.

| Actor | May claim/request | May approve or modify | Must never authorize | Intended verification and unavailable-proof behavior |
|---|---|---|---|---|
| Repository owner | Request evaluations; establish project authority | Enroll/re-enroll root; approve policy; authorize targets they control; approve exact exceptions/releases; designate bounded delegates | Claim independent Red Team acceptance or make absent evidence pass | Owner key/purpose in enrolled root; exact approval record. Missing proof: refuse approval and keep #1/#3 gates closed. |
| Trusted policy issuer / delegated approver | Issue policy approval within delegation | Modify proposed policy text; approve exact policy digest if delegated | Expand delegated repository/purpose/expiry; authorize targets, exceptions, or releases unless separately delegated; self-expand role | Signature verifies under enrolled/delegated key with exact role, scope, sequence and time. Unknown/expired delegation: policy unavailable, `INDETERMINATE`/refused. |
| Security reviewer | Review evidence and propose a disposition | Approve narrowly scoped finding exception only if separately authorized for that role | Change mandatory checks; grant target scope; turn missing execution into PASS; approve release unless separately owner-authorized | Root-authenticated exception role and signed, finding-bound record. Missing proof: exception invalid; original policy applies. |
| Test requester | Request a run for an exact repo/commit, mode and policy profile | Select only a profile and scope already permitted by trusted policy | Define policy, waive checks, authorize targets, change trust store, approve results/releases | CI identity claims or local operator attribution are recorded; they do not grant additional roles. Unavailable identity may prevent the run under owner policy. |
| Target owner / active-test authorizer | Identify target and request bounded testing | Approve explicit target/category/time scope they control | Authorize unrelated targets, broaden policy, waive check requirements, or approve stable release by target consent alone | Separately authenticated target-authority proof and typed target record; proof method is unresolved. No proof or expired scope: active stage `REFUSED`. |
| Local SAR process | Parse/run under installed configuration; report observed state | Nothing; it is a verifier/executor, not an approval principal | Enroll or replace root from project input; invent approval; certify its own executable integrity | Verify against trust state established outside checkout. Missing/tampered state: refuse trusted evaluation. Compromised executable remains outside its own proof. |
| CI workflow | Request/run declared jobs; emit run/artifact provenance | Nothing about policy or target authority merely because it runs | Issue owner policy, approve its own workflow change, assert skipped work ran, promote release | Verify GitHub OIDC/API identity, repo ID, workflow/ref/SHA, run ID and attempt against independent expectations. Identity proves context only. |
| Independent Red Team reviewer | Review exact immutable candidate and report findings/recommendation | Independent review disposition within the review engagement | Owner acceptance, implementation authorization, or stable release unless the owner separately grants that authority | Reviewer identity and exact SHA in review record. No report means acceptance remains pending. |
| ECE verifier | Verify evidence properties within the exact accepted ECE scope | Its own bounded verification findings only | Decide SAR scan adequacy, vulnerability absence, policy authority, target consent, or release | Pin accepted ECE implementation/contract SHA; verify only supported claims. Unavailable or unsupported input remains unknown/limited. |
| ATM read-only consumer | Consume verified output | Nothing in SAR | Change SAR policy, authorize tests/exceptions, or establish security authority | Treat data as read-only and preserve its verification limits; unavailable evidence stays unavailable. |
| Future AI agent (v2 only) | Suggest hypotheses, plans, explanations | Nothing; outputs remain untrusted suggestions | Approve its generated policy, result, exception, target, privilege escalation, or release; approve its own output | No trust role or signing key. Any AI feature is off by default and separately authorized; output cannot satisfy an approval field. |

## CI, LOCAL, and HYBRID trust rules

Mode changes where stages execute; they never lower mandatory policy, approval, or target requirements.

### CI

- Bind GitHub repository numeric ID, full source commit SHA, event/ref, workflow identity, workflow run ID, and run attempt. Verify provider data from an authenticated source under explicitly configured expectations, not from fields in the scanner manifest alone.
- GitHub OIDC `id-token: write` enables requesting an identity token; it does not itself grant resource write access or policy authority. A relying party must check issuer, audience, repository identity, workflow identity/ref, and relevant run claims. Treat the token as execution identity, not owner policy approval.
- Use minimum `GITHUB_TOKEN` permissions and no long-lived owner signing key in the scanning job. Do not place the policy root private key in repository or organization secrets exposed to untrusted code. A CI job executing code cannot issue the policy it verifies.
- Verify both the required-check configuration and the actual run/jobs for the exact head SHA and attempt. GitHub documents that a conditionally skipped job can report success for dependent checks; a required status name alone is not evidence that every expected SAR stage executed. An aggregator must reconcile actual expected jobs/stages, and missing/skipped/conditional mandatory work cannot yield SAR PASS.
- Where configured, pin expected status updates to a specific GitHub App and review bypass permissions. Rulesets/status checks are repository administration and presently absent in SAR (#10). Do not represent this as enforced until configured and independently checked.
- A protected GitHub Actions environment with required reviewers can gate a job and its environment secrets; self-review prevention is configurable. Such a gate can be supplementary human approval, but it does not by itself prove the reviewer's SAR role, authenticate project policy, or authorize an active target. See the owner-decision and authority matrix above.
- Do not execute untrusted pull-request content in privileged `pull_request_target` contexts. GitHub warns that checking out and running untrusted code in a privileged workflow risks secrets/token exposure. Keep workflows read-only/minimal where possible and separate trusted workflow definition from untrusted source execution.
- Artifact attestations can bind a subject digest to workflow/build provenance. They do not prove scanner completeness, policy owner approval, or correctness of a security conclusion. Verify the attestation against preconfigured identity/root expectations, not merely its presence.

### LOCAL

- Use the same enrolled root, policy bytes, sequence floor and owner-authorized repository ID as CI. Bind the actual full commit SHA and immutable run plan. An operator may request but cannot grant policy or target authority.
- The trust store is outside the scanned checkout and may be used offline if valid policy material is already enrolled. Record the last verified policy/root state and `freshness_as_of`.
- Offline mode cannot discover a new revocation or prove that the cached policy remains the latest. If owner policy sets a freshness bound and the local snapshot exceeds it, or the clock cannot support expiry evaluation, refuse execution requiring fresh authorization or yield INDETERMINATE; never silently accept stale state.
- The same-user host can alter files, clock, process memory and outputs. Local verification does not defend against a compromised operating system, user account, SAR binary or signing key.

### HYBRID

- CI and LOCAL stages share one signed policy approval, exact repository ID and commit SHA, immutable parent plan ID/digest, expected check inventory, and one parent run identity. Each stage has a unique stage ID/attempt, mode and location, authorization references and artifact digests.
- A stage cannot change policy, scope or expected checks. Active authorization must name the exact target and categories for that stage and remain valid for execution; the authorization is separate from a source-only policy.
- Reconcile all expected mandatory stages. Missing, stale, revoked, expired, duplicated-conflicting, wrong-attempt, different-policy, different-commit or mismatched-artifact stages prevent complete/PASS. Do not combine receipts across parent runs or use a newer CI run to refresh an older local receipt without a newly bound parent plan.
- A required stage unavailable because of network/offline constraints remains missing/incomplete. Another successful scanner cannot satisfy it. Do not call cross-mode execution an isolation control.

### Active testing gate

No DAST or fuzz target may be contacted until later milestones implement and independently validate both (a) target-owner authorization for the exact target and test categories and (b) the applicable isolation, redirect/DNS handling and egress controls. A signed target record alone does not prove those controls exist. Until then, any active stage is `REFUSED`; a source-only result must not imply that active scope was covered.

## Expiry, revocation, rollback, and offline guarantees

| Condition | Proposed result and limit |
|---|---|
| No trust anchor, invalid signature, unsupported purpose/schema, unrecognized issuer, or mismatched repository/policy digest | `REFUSED` before trusted evaluation. No policy PASS. |
| Valid signature but expired/not-yet-valid key, delegation or statement, known revoked key/delegation, or sequence below locally persisted floor | Reject approval; do not use it. Run not started: `REFUSED`; if discovered after start: cancel affected work where feasible, mark execution `INCOMPLETE`, and decision `INDETERMINATE` unless a valid blocking finding is already established. A signed issue time is not trusted time by itself. |
| Offline with a valid cached root and policy and no known revocation | May evaluate only within owner-approved expiry/freshness limits and the host-clock assumption; output states revocation freshness is unknown since `freshness_as_of`. No claim of current global revocation status. |
| No trusted clock or stale freshness snapshot where expiry/revocation freshness is required | `REFUSED` for actions requiring current authorization or `INDETERMINATE` for an already started assessment. Never infer PASS. |
| Restored old trust-store backup / unseen newer policy sequence | Reject rollback when a newer local floor is retained. If the entire floor was rolled back or a new installation has no fresh reference, detection is impossible without an external freshness source; mark unknown and require re-enrollment/refresh under owner policy. |
| Root signing key lost | Stop trusted policy approval. Owner re-enrolls a replacement through the independently verified bootstrap channel. Recovery cannot be inferred from a repository commit. |
| Root/delegate key compromised | Treat affected approvals as untrusted from the earliest credible compromise time. A delegate is revoked by newer root-authenticated state. If root is compromised, use out-of-band re-enrollment; signatures from the compromised root cannot safely authenticate the repair. |
| Host/runner compromised | No trustworthy SAR result can be established by that host alone, even with a valid policy signature or GitHub provenance. A separate trusted runner/verifier is needed; that architecture is unresolved. |

These are not perfect anti-rollback/revocation guarantees. TUF documents root roles, versioned metadata and expiration as mechanisms for update-system rollback/freeze resistance, but SAR is not proposing a full TUF client. A cached signature without fresh state cannot reveal a newer revocation. A trusted clock, durable monotonic state, and online current metadata source each have separate compromise/availability assumptions.

## Future GOV-01 boundary and implementation prerequisites

No implementation starts in R2. Before any future runtime may report trusted security PASS, its authorized scope must include:

- An owner-approved, independently enrolled trust anchor and verified approval authentication; no project-supplied key fallback.
- Trusted policy selection bound to policy bytes/digest, purpose, repository ID, sequence, validity and authorized issuer.
- Fail-closed behavior for missing/invalid/stale/revoked approvals and unknown repository identity.
- Explicit mandatory-check inventory and the independent execution/coverage semantics in `SECURITY_POLICY_MODEL.md`.
- Reproducible negative fixtures for signature/key/policy substitution, expiry, sequence rollback, wrong target repository, missing required stages, stale/invalid GitHub context, and all ten cases below.
- A separate exact target authorization mechanism before active tests; active scanning stays deferred until GOV-03 validates isolation and egress controls.

Synthetic test fixtures may model authorized records, invalid signatures, key substitutions, expiries and stage reconciliation, but must be visibly test-only and must never use or imply a real owner trust anchor. They can test parsing and state transitions; they do not prove owner enrollment or deployment readiness.

Deferred: real scanner execution; DAST/fuzz; network enforcement; external authenticated GitHub evidence ingestion; production key custody integrations; full TUF; ECE interoperability; AI security review/adversarial agents; stable-release authorization and `main` promotion. GOV-01, if separately authorized, is a bounded Rust-first proof of concept rather than a deployable security product. The initial trust root must be independently established before SAR is asked to verify project policy; the executable cannot establish its own trustworthiness.

## Required synthetic negative tests (not executed)

All cases are future test specifications only. No real targets, keys, signatures, or policies were generated or attacked in R2.

| ID | Attacker input and boundary | Invalid claim / precondition | Expected oracle and proposed control | Future milestone / residual limitation |
|---|---|---|---|---|
| **RT01-A — self-approved policy and matching digest** | Operator supplies altered policy, its matching SHA-256 and `approved_by=owner`; policy-input boundary | Matching bytes are claimed to be owner-approved | Digest matches but no trusted approval record; reject before execution as `REFUSED`, never PASS. Verify signature under pre-enrolled root and exact policy digest. | GOV-01 fixture. Does not protect a compromised verifier. |
| **RT01-B — substitute key and signed policy together** | Untrusted manifest supplies attacker key, policy and valid signature; trust-store boundary | Self-signed pair claims to establish its own root | Signature under unrecognized key is rejected; project files cannot replace external trust state. | GOV-01 fixture. Initial fingerprint enrollment still depends on owner channel. |
| **RT01-C — trust material from unprotected branch** | Pull request changes trust bundle/policy/approval URL; repository-to-runner boundary | Branch contents claim to be trusted root/policy | Ignore project-supplied anchor; use independently enrolled root or refuse. | GOV-01/04. GitHub branch protections currently absent; admin compromise remains. |
| **RT01-D — skipped required CI job reported successful** | Workflow condition skips mandatory job while GitHub dependent check is green; CI job graph boundary | Green status is claimed as complete required scan | Compare trusted required-check inventory with actual job/attempt conclusions; mandatory skip makes execution incomplete and policy INDETERMINATE, not PASS. | GOV-01 fixtures, GOV-04 CI. GitHub semantics/configuration must be rechecked. |
| **RT01-E — forged/unauthorized CI status source** | Unapproved actor or integration posts a same-name status; provider evidence boundary | Status name claims trusted SAR result | Verify configured status source/App and authenticated repo/SHA/run; reject untrusted source. | GOV-04. Repository write/admin authority remains a provider trust assumption. |
| **RT01-F — signing key exposed to scanning agent** | Workflow/source-controlled step reads a signing key; signer boundary | Valid signature is claimed to prove owner approval although runner can sign | No owner/private signing key in scanning job; verifier rejects workflow key absent explicit trusted role. | GOV-01/04. Compromise of owner signing device remains critical. |
| **RT01-G — replay old valid policy** | Old signed policy with lower sequence is replayed; local freshness boundary | Valid old signature claims current authority | Reject below stored sequence; expired/stale current-state snapshot cannot PASS. Test whole-store rollback as a known undetectable case without external freshness. | GOV-01. No perfect offline rollback defense if monotonic state is restored. |
| **RT01-H — source-only approval reused for active DAST** | Run changes category/target after receiving source-analysis approval; policy/target boundary | Policy signature is claimed to authorize an external host | Purpose mismatch: active stage `REFUSED` without separate target-owner record and validated later isolation/egress controls. | GOV-03. Target ownership verification remains an open design item. |
| **RT01-I — policy for repository X applied to Y** | Manifest substitutes repository name/URL or checkout; repository identity boundary | X's valid approval is claimed for Y | Compare stable provider repository ID in approval, authenticated provider context, checkout origin and full commit; mismatch refuses the policy/run. | GOV-01/04. Local identity without trusted provider metadata is limited. |
| **RT01-J — compromised runner with valid policy** | Attacker controls host/SAR process but policy signature is valid; executable trust boundary | Correct policy signature is claimed to prove honest scan execution | Documented oracle: do not claim host-independent correctness from local output; independent runner/verifier evidence required, otherwise assurance remains limited/INDETERMINATE. | GOV-01 trust boundary and later verifier design. A compromised execution host can fabricate outputs. |

## Source facts and implementation status

**VERIFIED SOURCE FACT:** GitHub rulesets can require status checks and allow selection of a particular GitHub App as the expected status source; actors with write permissions can otherwise set statuses. GitHub documents that a conditionally skipped Actions job reports success for dependent jobs. Branch/ruleset controls do not prove scan correctness.

**VERIFIED SOURCE FACT:** GitHub OIDC requires workflow permission to request a token; the permission alone does not grant resource write access. Identity claims must be checked by a relying party. Artifact attestations describe build provenance. SLSA verification guidance recommends a preconfigured root of trust and matching expectations; provenance is not a security-scan quality verdict.

**VERIFIED SOURCE FACT:** DSSE binds the payload type and bytes in its signature input but does not define algorithms or key authority. TUF specification 1.0.37 describes root/role metadata, signatures, expiry and version checks; those ideas inform this proposal, but no TUF implementation is selected.

**IMPLEMENTED/TESTED FACT:** None of the trust bootstrap, signature verification, revocation, CI evidence ingestion, target authorization, key management or negative test cases in this document is implemented or tested in SAR. Source links and retrieval dates are recorded in [`SOURCE_PROVENANCE.md`](../SOURCE_PROVENANCE.md).

## References

- [GitHub ruleset status-check sources](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets)
- [GitHub required-check behavior for skipped jobs](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks)
- [GitHub Actions OIDC reference](https://docs.github.com/en/actions/reference/security/oidc)
- [GitHub artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations)
- [GitHub secure use of `pull_request_target`](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target)
- [SLSA v1.2 artifact verification](https://slsa.dev/spec/v1.2/verifying-artifacts)
- [DSSE protocol and envelope](https://github.com/secure-systems-lab/dsse)
- [TUF specification 1.0.37](https://theupdateframework.github.io/specification/)
- [RFC 8032 — EdDSA](https://datatracker.ietf.org/doc/html/rfc8032)
- [RustCrypto `ed25519-dalek` 3.0.0 `VerifyingKey` API](https://docs.rs/ed25519-dalek/3.0.0/ed25519_dalek/struct.VerifyingKey.html) — research candidate only; no dependency selection.
- [Sigstore security model](https://docs.sigstore.dev/about/security/) — considered for CI identity/provenance only; not selected as SAR policy authority.
