#!/usr/bin/env bash
# GOV-02 PILOT-01: one authorized synthetic Linux x64 Gitleaks v8.30.1 invocation.
set -Eeuo pipefail
IFS=$'\n\t'
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ "${GOV02_PILOT_ONCE_AUTHORIZED:-}" == "EXPLICIT_ONESHOT" ]] || { echo "BLOCKED:NOT_AUTHORIZED" >&2; exit 1; }
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || { echo "BLOCKED:LINUX_X64_REQUIRED" >&2;exit 1; }
for tool in curl sha256sum python3 readelf docker timeout;do command -v "$tool" >/dev/null || { echo "BLOCKED:MISSING_TOOL:$tool" >&2;exit 1;};done
# This preflight invokes no Gitleaks executable and must succeed before acquisition.
bash "$HERE/preflight.sh"
WORK="$(mktemp -d)"
CONTAINER=''
IMAGE=''
cleanup(){
  if [[ -n "$CONTAINER" ]];then docker rm -f "$CONTAINER" >/dev/null 2>&1 || true;fi
  if [[ -n "$IMAGE" ]];then docker image rm -f "$IMAGE" >/dev/null 2>&1 || true;fi
  rm -rf -- "$WORK"
}
trap cleanup EXIT
mkdir -p "$WORK/image" "$WORK/config" "$WORK/input" "$WORK/output"
printf '%s\n' 'SAR_INERT_DEMO_ABCD1234' > "$WORK/input/positive.txt"
printf '%s\n' 'ordinary harmless content without an inert marker' > "$WORK/input/negative.txt"
cat > "$WORK/config/pilot.toml" <<'EOF_CONFIG'
title = "SAR artificial Gitleaks pilot — test-only"
[[rules]]
id = "sar-pilot-inert-rule"
description = "matches only fabricated SAR_INERT_DEMO sequences"
regex = '''SAR_INERT_DEMO_[A-Z0-9]{8}'''
keywords = ["SAR_INERT_DEMO_"]
EOF_CONFIG
python3 - "$WORK/input" "$WORK/config" <<'PY'
import pathlib,sys
source,conf=map(pathlib.Path,sys.argv[1:])
if {p.name for p in source.iterdir()}!={"positive.txt","negative.txt"}:raise SystemExit("BLOCKED:CORPUS_INVENTORY")
if {p.name for p in conf.iterdir()}!={"pilot.toml"}:raise SystemExit("BLOCKED:CONFIG_INVENTORY")
if any(not p.is_file() or p.is_symlink() for p in (*source.iterdir(),*conf.iterdir())):raise SystemExit("BLOCKED:UNSAFE_CORPUS")
if (source/"positive.txt").read_bytes()!=b"SAR_INERT_DEMO_ABCD1234\n":raise SystemExit("BLOCKED:CORPUS_CHANGED")
if (source/"negative.txt").read_bytes()!=b"ordinary harmless content without an inert marker\n":raise SystemExit("BLOCKED:NEGATIVE_CHANGED")
PY
chmod 0755 "$WORK/input" "$WORK/config"
chmod 0644 "$WORK"/input/* "$WORK"/config/*
chmod 0777 "$WORK/output" # Disposable container-only, never the checkout.
echo "PILOT_CORPUS_SYNTHETIC_ONLY"
sha256sum "$WORK"/input/* "$WORK"/config/* >"$WORK/controlled-input-digests.private"
EXPECTED_ARCHIVE_SHA="551f6fc83ea457d62a0b98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
URL="https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz"
curl --fail --location --silent --show-error --max-time 90 --retry 0 -o "$WORK/gitleaks.tar.gz" "$URL"
echo "$EXPECTED_ARCHIVE_SHA  $WORK/gitleaks.tar.gz" | sha256sum --check --status || { echo "BLOCKED:ARCHIVE_DIGEST_MISMATCH" >&2;exit 1; }
echo PILOT_RELEASE_ARCHIVE_DIGEST_MATCH
python3 - "$WORK/gitleaks.tar.gz" "$WORK/image/gitleaks" <<'PY'
import pathlib,sys,tarfile
archive,target=map(pathlib.Path,sys.argv[1:])
with tarfile.open(archive,"r:gz") as t:
    entries=t.getmembers()
    if not 1<=len(entries)<=20:raise SystemExit("BLOCKED:ARCHIVE_MEMBER_COUNT")
    executables=[]
    for m in entries:
        name=m.name.removeprefix("./")
        if not m.isfile() or m.issym() or m.islnk() or m.name.startswith("/") or name.startswith("../") or "/../" in name:
            raise SystemExit("BLOCKED:ARCHIVE_UNSAFE_MEMBER")
        if len(name)>128 or m.size>30000000:raise SystemExit("BLOCKED:ARCHIVE_UNBOUNDED_MEMBER")
        if name=="gitleaks":executables.append(m)
    if len(executables)!=1:raise SystemExit("BLOCKED:EXECUTABLE_MISSING")
    with t.extractfile(executables[0]) as source,target.open("xb") as dst:
        data=source.read(30000001)
        if len(data)>30000000:raise SystemExit("BLOCKED:EXECUTABLE_TOO_LARGE")
        if len(data)<20 or data[:4]!=b"\x7fELF" or data[4]!=2 or data[5]!=1 or int.from_bytes(data[18:20],"little")!=62:
            raise SystemExit("BLOCKED:WRONG_EXECUTABLE_FORMAT")
        dst.write(data)
target.chmod(0o555)
PY
if readelf -l "$WORK/image/gitleaks" | grep -q 'INTERP';then echo "BLOCKED:DYNAMIC_EXECUTABLE" >&2;exit 1;fi
EXEC_DIGEST="$(sha256sum "$WORK/image/gitleaks" | cut -d' ' -f1)"
[[ "$EXEC_DIGEST" =~ ^[a-f0-9]{64}$ ]] || { echo "BLOCKED:EXECUTABLE_DIGEST_FAILED" >&2;exit 1; }
echo "PILOT_EXTRACTED_EXECUTABLE_SHA256=$EXEC_DIGEST"
cat > "$WORK/image/Dockerfile" <<'EOF_DOCKER'
FROM scratch
COPY gitleaks /gitleaks
USER 65532:65532
ENTRYPOINT ["/gitleaks"]
EOF_DOCKER
IMAGE="sar-gov02-gitleaks:${GITHUB_RUN_ID:-local}-$$"
docker build --network none --pull=false -q -t "$IMAGE" "$WORK/image" >/dev/null
CONTAINER="sar-gov02-real-once-${GITHUB_RUN_ID:-local}-$$"
ARGS=(dir /input --config=/config/pilot.toml --report-format=json --report-path=/output/report.json --exit-code=23 --no-banner --redact=100 --ignore-gitleaks-allow --max-archive-depth=0 --max-target-megabytes=1)
docker create --name "$CONTAINER" --network none --read-only --user 65532:65532 \
  --cap-drop ALL --security-opt no-new-privileges:true --memory 128m --memory-swap 128m \
  --cpus 0.5 --pids-limit 32 \
  --mount "type=bind,source=$WORK/input,target=/input,readonly" \
  --mount "type=bind,source=$WORK/config,target=/config,readonly" \
  --mount "type=bind,source=$WORK/output,target=/output" \
  "$IMAGE" "${ARGS[@]}" >/dev/null
docker inspect "$CONTAINER" >"$WORK/container-spec.json"
python3 "$HERE/verify_spec.py" "$WORK/container-spec.json" "$WORK/input" "$WORK/output" none "$WORK/config" /gitleaks "${ARGS[@]}"
echo PILOT_SCANNER_CONTAINER_SPEC_VERIFIED
set +e
timeout --kill-after=5s 60s docker start -a "$CONTAINER" >"$WORK/native-output.private" 2>&1
START_RC=$?
set -e
if [[ "$START_RC" == 124 || "$START_RC" == 137 ]];then echo "BLOCKED:SCANNER_TIMEOUT" >&2;exit 1;fi
[[ $(wc -c < "$WORK/native-output.private") -le 32768 ]] || { echo "BLOCKED:EXCESSIVE_NATIVE_DIAGNOSTIC" >&2;exit 1; }
EXIT_CODE="$(docker inspect -f '{{.State.ExitCode}}' "$CONTAINER")"
echo "PILOT_SCANNER_NATIVE_EXIT=$EXIT_CODE"
[[ "$EXIT_CODE" == 23 ]] || { echo "BLOCKED:UNEXPECTED_SCANNER_EXIT" >&2;exit 1; }
docker cp "$CONTAINER:/output/report.json" "$WORK/report.json" >/dev/null 2>&1 || { echo "BLOCKED:REPORT_MISSING" >&2;exit 1; }
python3 "$HERE/inspect_report.py" "$WORK/report.json"
REPORT_SHA="$(sha256sum "$WORK/report.json" | cut -d' ' -f1)"
[[ "$REPORT_SHA" =~ ^[a-f0-9]{64}$ ]] || { echo "BLOCKED:REPORT_DIGEST_MISSING" >&2;exit 1; }
echo "PILOT_RESTRICTED_REPORT_SHA256=$REPORT_SHA"
docker rm -f "$CONTAINER" >/dev/null
CONTAINER=''
echo GOV_02_PILOT_01_SYNTHETIC_SCAN_OBSERVED
