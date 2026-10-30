# Trust boundaries

**Status:** ARCHITECTURAL PROPOSAL; no controls implemented.

| Boundary | Untrusted input / actor | Proposed rule |
|---|---|---|
| Owner trust root → SAR trust store | Project checkout, operator manifest, repo workflow, supplied key/signature pair | Enroll verification material only after independent owner fingerprint verification; store outside scanned checkout. Missing/unknown anchor means `REFUSED`. A signature/key pair delivered together in an untrusted manifest is not bootstrap. |
| Policy authority → evaluation | Policy bytes, digest, claimed issuer/role, Git branch/commit | Verify typed approval against an independently enrolled key, purpose, repository identity, policy digest, sequence and validity. Hash/commit alone is not approval. See [trust bootstrap and policy authority](TRUST_BOOTSTRAP_AND_POLICY_AUTHORITY.md). |
| Operator → SAR | Manifest, target, selected mode, policy | Require explicit scope and authorization; bind run to repository and commit; reject ambiguous target scope |
| SAR → source tree | Source files, build scripts, archives | Treat all repository content as hostile data; never execute project scripts by default |
| SAR → scanner process | Tool binary/image, arguments, environment, output | Pin identity, use argument arrays (no shell), minimal environment/capabilities, bounded resources/output |
| Scanner → parser | JSON/SARIF/SBOM/logs | Parse with size/depth limits; validate schemas; no external entity/network resolution; retain raw digest and parse errors |
| Runner → network/target | DNS, redirects, proxy, egress | Default deny for active tests; explicit authorized target allowlist and egress policy; enforce outside attacker-controlled config |
| CI provider → SAR execution identity | OIDC claims, workflow/run/check/artifact metadata | Verify issuer/audience/repository/workflow/run/attempt against independent expectations. These claims support execution provenance; they do not grant policy-issuer, target-owner, exception, or release authority. |
| Host/SAR executable → trust decision | Local binary, operating system, clock, persistent trust store | A valid policy signature does not establish executable integrity. Compromised host, runner, clock or rolled-back trust store can fabricate outputs or hide revocation; do not claim host-independent assurance. |
| SAR → report/evidence | Findings, excerpts, secrets, paths | Minimize sensitive content, redact carefully, apply output access controls, keep raw artifact references explicit |
| SAR ↔ ECE | SAR claims and exported evidence | ECE independently verifies only its declared inputs and limits; it does not prove scan adequacy or absence of vulnerabilities |
| SAR ↔ optional AI | Source/report content, provider | v1 no AI. Future opt-in must be separate; untrusted content cannot grant tools, network or write authority |

A container is process packaging, not proof of a complete boundary. Its host kernel, mounted paths, daemon/socket access, credentials, capabilities, network, runtime configuration and resource limits matter. Rootless execution or a VM may improve separation but also requires threat-specific validation. Containerized untrusted build steps can still attack the host through a vulnerable runtime or exposed mounts.

**REQUIRED FUTURE TEST:** negative tests for host mounts, Docker socket visibility, network egress, symlink/archive escape, report parser denial of service, process tree cancellation, temp-file cross-run access and secret leakage.
