# Trust boundaries

**Status:** ARCHITECTURAL PROPOSAL; no controls implemented.

| Boundary | Untrusted input / actor | Proposed rule |
|---|---|---|
| Operator → SAR | Manifest, target, selected mode, policy | Require explicit scope and authorization; bind run to repository and commit; reject ambiguous target scope |
| SAR → source tree | Source files, build scripts, archives | Treat all repository content as hostile data; never execute project scripts by default |
| SAR → scanner process | Tool binary/image, arguments, environment, output | Pin identity, use argument arrays (no shell), minimal environment/capabilities, bounded resources/output |
| Scanner → parser | JSON/SARIF/SBOM/logs | Parse with size/depth limits; validate schemas; no external entity/network resolution; retain raw digest and parse errors |
| Runner → network/target | DNS, redirects, proxy, egress | Default deny for active tests; explicit authorized target allowlist and egress policy; enforce outside attacker-controlled config |
| SAR → report/evidence | Findings, excerpts, secrets, paths | Minimize sensitive content, redact carefully, apply output access controls, keep raw artifact references explicit |
| SAR ↔ ECE | SAR claims and exported evidence | ECE independently verifies only its declared inputs and limits; it does not prove scan adequacy or absence of vulnerabilities |
| SAR ↔ optional AI | Source/report content, provider | v1 no AI. Future opt-in must be separate; untrusted content cannot grant tools, network or write authority |

A container is process packaging, not proof of a complete boundary. Its host kernel, mounted paths, daemon/socket access, credentials, capabilities, network, runtime configuration and resource limits matter. Rootless execution or a VM may improve separation but also requires threat-specific validation. Containerized untrusted build steps can still attack the host through a vulnerable runtime or exposed mounts.

**REQUIRED FUTURE TEST:** negative tests for host mounts, Docker socket visibility, network egress, symlink/archive escape, report parser denial of service, process tree cancellation, temp-file cross-run access and secret leakage.
