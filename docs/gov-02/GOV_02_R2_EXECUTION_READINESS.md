# GOV-02 R2 — proposed future execution gate

DESIGN ONLY, no execution authorization. Research 2026-10-31: [v8.30.1 release](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1), [directory mode source](https://github.com/gitleaks/gitleaks/blob/v8.30.1/cmd/directory.go), [flags and loader](https://github.com/gitleaks/gitleaks/blob/v8.30.1/cmd/root.go), [README](https://github.com/gitleaks/gitleaks/blob/v8.30.1/README.md), [license](https://github.com/gitleaks/gitleaks/blob/v8.30.1/LICENSE). CLI distribution license and separately licensed Action must not be conflated. No binaries or rules were downloaded.

The GitHub release metadata advertises a checksums file and these assets; archive digest is not extracted executable digest and GitHub metadata is not independent owner approval:

| platform | official asset | GitHub-reported SHA-256 of archive |
|---|---|---|
| Linux x64 | [linux_x64](https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz) | `551f6fc83ea457d62a0b98237cbad105af8d557003051f41f3e7ca7b3f2470eb` |
| Windows x64 | [windows_x64](https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_windows_x64.zip) | `d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332af4e` |
| macOS ARM64 | [darwin_arm64](https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_darwin_arm64.tar.gz) | `b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5` |

Prior to a separately authorized pilot, owner independently approves executable digest or authenticated upstream release provenance and trust anchor outside checkout. The checksum and binary from a single compromised release source are not independent authentication. Record release, platform, acquisition, archive and extracted executable digests; replacement requires new review. Verify the exact executable immediately before launch and protect against path replacement/TOCTOU; unsupported handle-bound execution or untrusted mutable location is a no-go.

## Candidate invocation contract

A future fixed argv could select `dir`, a controlled disposable directory, explicit owner-approved configuration, JSON report path inside controlled output, `--ignore-gitleaks-allow`, `--max-archive-depth=0`, and `--redact=100`; exact argv and behavior require verification before authorization. No project command, Git history, target network or credential validation. Upstream config precedence includes `--config`, environment variables and target `.gitleaks.toml`; explicit controlled config plus scrubbed environment and controlled input are required. Source also independently loads source `.gitleaksignore` even when ignore path is set: refuse if present in the generated input; do not assume flag disables this. Baseline, enable-rule and configuration allowlists can suppress findings. Inline allow must be neutralized and tested. `--follow-symlinks` is false by default, yet symlink and race escapes require OS containment. File-size exclusions, decode and archive depth must be recorded; an unreadable or skipped file is incomplete. `--redact` is not a substitute for restricted report storage. Exit 1 can mean a finding or error; exit zero and a JSON array do not demonstrate completeness.

## Platform gates

- Linux: investigate mount/user/network namespaces, immutable read-only input mount, cgroup v2 memory/pids, seccomp and descendant cleanup. [Kernel cgroup documentation](https://docs.kernel.org/6.6/admin-guide/cgroup-v2.html). Kernel policy, namespace privileges, network denial and escape resistance need direct tests.
- Windows: investigate restricted token/AppContainer filesystem and network capabilities plus Job Objects for limits and process-tree cleanup. [Microsoft isolation](https://learn.microsoft.com/en-us/windows/security/book/application-security-application-isolation). Job Objects alone do not deny networking or filesystem access. Exact packaging and compatibility unresolved.
- macOS: investigate signed App Sandbox helper entitlements and filesystem grants, without outgoing network entitlement; [Apple App Sandbox](https://developer.apple.com/documentation/security/app-sandbox). Signing, helper compatibility, resource and child-process limits remain unresolved; no claim that an ordinary shell timeout is sandboxing.

On every OS require independently pinned executable, immutable argv, disposable generated corpus, read-only input where enforceable, separate restricted output, no inherited credentials, minimal environment, enforceable egress denial, timeout, bounded memory/process/output, cancellation and descendant cleanup. Validate symlink/archive escape and no external file access. If any required control cannot be demonstrated, return `PLATFORM_EXECUTION_BLOCKED`; no downgrade or fallback.

## Evidence, negative tests and authorization

A future receipt must bind parent run/plan/stage/attempt, actual approved executable identity, argv, controlled corpus file inventory and digests, configuration/rules digest, environment policy, observed exit, stdout/stderr status, report byte digest, truncation/errors/skips and limitations. Separate observed facts from process assertions. A synthetic expected positive and negative corpus tests only those fixtures; it does not prove universal detection or production policy PASS.

Future test oracles: swapped binary and post-verification replacement => refuse; project `.gitleaks.toml`, `.gitleaksignore`, inline allow or baseline => refuse or demonstrate neutralization; missing/truncated report or unreadable required file => incomplete; external network and symlink escapes => denied and independently observed; excessive output, memory, time or descendants => bounded and incomplete. Actual exit/report semantics, archive behavior and all OS controls remain untested. No scanner or rule downloads/execution occurred in R2.

Proposed later owner authorization: one specified platform, independently pinned Gitleaks binary and approved fixed config, one disposable invented corpus, passive `dir` only, controlled no-network environment after isolation is independently validated, restricted report handling, no production claims; acquisition, execution and each expanded platform require explicit approval. No permission is implied by this design.
