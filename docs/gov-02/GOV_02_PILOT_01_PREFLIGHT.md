# GOV-02 PILOT-01 — scanner-disabled Linux preflight

**Scope:** development-only preparation for the authorized PILOT-01. No Gitleaks archive, binary, rule pack, real source scan, native scanner report or operational security PASS is included.

The [preflight workflow](../../.github/workflows/gov02-pilot-01-preflight.yml) triggers only when the workflow file or `scripts/gov02/pilot01/**` changes on `development`. It runs on GitHub-hosted Ubuntu 24.04 x64 with `contents: read` and checkout `persist-credentials: false`. It cannot invoke a scanner because it has no scanner acquisition or invocation path. `main` remains frozen.

The original `probe.c` is compiled as a static Linux x64 binary and copied into a `FROM scratch` image, without downloading any base image. Docker's actual container HostConfig is inspected for network mode, read-only root, nonroot user, dropped capabilities, no-new-privileges, 128 MiB RAM and swap limits, 0.5 CPU, 32 PIDs, and exactly two selected ephemeral mounts. The probe checks effective capabilities and NoNewPrivs from /proc, read-only generated input, root filesystem write refusal, and a receipt inside the only intended user bind output. Docker runtime-provided virtual mounts such as /dev/shm may still be writable; this is not a proof of universal host confinement.

A listener bound to the **runner's local Docker bridge gateway** provides a real, local-only positive connectivity control via `--network bridge`. The matching negative probe uses `--network none` and must fail to reach that same endpoint. This demonstrates the specific Docker network boundary, not the absence of every possible egress or a complete kernel isolation proof.

A long-running disposable probe must time out and be removed. A Bash exit trap cleans up all containers, listener and ephemeral inputs. Failure of any required check makes the job fail, without falling back to direct host scanner execution.

**Execution result:** PENDING until GitHub Actions provides a real job ID, run attempt, exact SHA and logs. Rust GOV-01/GOV-02 CI runs independently. The real Gitleaks one-shot workflow is not created in this preflight-only commit, and must not be inferred from a green preflight.

The previous local `.gitignore` research-PDF edit belongs to the author's local machine and is not staged or changed by this remote commit.
