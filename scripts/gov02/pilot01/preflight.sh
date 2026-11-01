#!/usr/bin/env bash
# GOV-02 PILOT-01 scanner-DISABLED Linux preflight.
set -Eeuo pipefail
IFS=$'\n\t'
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d)"
CONTAINERS=()
LISTENER_PID=''
cleanup(){
  local n
  for n in "${CONTAINERS[@]}"; do docker rm -f "$n" >/dev/null 2>&1 || true; done
  if [[ -n "$LISTENER_PID" ]]; then kill "$LISTENER_PID" >/dev/null 2>&1 || true; wait "$LISTENER_PID" >/dev/null 2>&1 || true; fi
  rm -rf -- "$WORK"
}
trap cleanup EXIT
if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then echo 'BLOCKED:LINUX_X64_REQUIRED' >&2;exit 1;fi
for c in docker cc python3 timeout;do command -v "$c" >/dev/null || { echo "BLOCKED:TOOL_MISSING:$c" >&2; exit 1; };done
docker info --format '{{.ServerVersion}}' >/dev/null
mkdir -p "$WORK/image" "$WORK/input" "$WORK/output"
printf '%s\n' SAR_INERT_DEMO_ABCD1234 >"$WORK/input/marker.txt"
chmod 0755 "$WORK/input";chmod 0644 "$WORK/input/marker.txt"
chmod 0777 "$WORK/output" # Disposable GitHub runner-only directory.
cc -std=c11 -O2 -Wall -Wextra -Werror -static -o "$WORK/image/probe" "$HERE/probe.c"
cat >"$WORK/image/Dockerfile" <<'EOF_DOCKER'
FROM scratch
COPY probe /probe
USER 65532:65532
ENTRYPOINT ["/probe"]
EOF_DOCKER
IMAGE="sar-gov02-preflight:${GITHUB_RUN_ID:-local}-$$"
docker build --network none --pull=false -q -t "$IMAGE" "$WORK/image" >/dev/null
PREFIX="sar-gov02-${GITHUB_RUN_ID:-local}-$$"
COMMON=(--read-only --user 65532:65532 --cap-drop ALL --security-opt no-new-privileges:true
 --memory 128m --memory-swap 128m --cpus 0.5 --pids-limit 32
 --mount "type=bind,source=$WORK/input,target=/input,readonly"
 --mount "type=bind,source=$WORK/output,target=/output")
make_checked(){
  local name="$1" mode="$2";shift 2
  docker create --name "$name" --network "$mode" "${COMMON[@]}" "$IMAGE" "$@" >/dev/null
  CONTAINERS+=("$name")
  docker inspect "$name" >"$WORK/spec.json"
  python3 "$HERE/verify_spec.py" "$WORK/spec.json" "$WORK/input" "$WORK/output" "$mode"
}
FS="$PREFIX-fs"
make_checked "$FS" none fs
timeout 20s docker start -a "$FS"
[[ "$(docker inspect -f '{{.State.ExitCode}}' "$FS")" == 0 ]]
[[ "$(cat "$WORK/output/receipt.txt")" == PREFLIGHT_FS_OK ]]
echo PREFLIGHT_FILESYSTEM_OK
# Local-only positive test on Docker bridge gateway; no external host contacted.
GATEWAY="$(docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}')"
[[ "$GATEWAY" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo BLOCKED:BRIDGE_UNAVAILABLE >&2;exit 1;}
python3 -u - "$GATEWAY" "$WORK/port" <<'PY' &
import socket,sys
ip,path=sys.argv[1:]
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind((ip,0));s.listen(4)
with open(path,"w",encoding="utf-8") as f:f.write(str(s.getsockname()[1]))
while True:
    c,_=s.accept();c.close()
PY
LISTENER_PID=$!
for attempt in {1..30};do [[ -s "$WORK/port" ]] && break;sleep 0.1;done
[[ -s "$WORK/port" ]] || { echo BLOCKED:LISTENER_UNAVAILABLE >&2;exit 1;}
PORT="$(cat "$WORK/port")"
POS="$PREFIX-positive"
make_checked "$POS" bridge net "$GATEWAY" "$PORT"
timeout 20s docker start -a "$POS"
[[ "$(docker inspect -f '{{.State.ExitCode}}' "$POS")" == 0 ]]
echo PREFLIGHT_LOCAL_NETWORK_POSITIVE_OK
NEG="$PREFIX-negative"
make_checked "$NEG" none net "$GATEWAY" "$PORT"
set +e
timeout 20s docker start -a "$NEG"
set -e
[[ "$(docker inspect -f '{{.State.ExitCode}}' "$NEG")" == 42 ]] || { echo BLOCKED:NETWORK_DENIAL_NOT_SHOWN >&2;exit 1;}
echo PREFLIGHT_NETWORK_NONE_NEGATIVE_OK
SL="$PREFIX-timeout"
make_checked "$SL" none sleep
docker start "$SL" >/dev/null
set +e
timeout 2s docker wait "$SL" >/dev/null
WAIT=$?
set -e
[[ "$WAIT" == 124 ]] || { echo BLOCKED:TIMEOUT_UNDEMONSTRATED >&2;exit 1;}
docker rm -f "$SL" >/dev/null
if docker inspect "$SL" >/dev/null 2>&1;then echo BLOCKED:CLEANUP_FAILED >&2;exit 1;fi
echo PREFLIGHT_TIMEOUT_CLEANUP_OK
echo GOV_02_PILOT_01_SCANNER_DISABLED_PREFLIGHT_PASS
