#!/usr/bin/env python3
"""Fail-closed check of Docker's actual HostConfig; scanner disabled."""
import json
import pathlib
import sys

def verify(spec, input_path, output_path, network):
    records=json.loads(pathlib.Path(spec).read_text(encoding="utf-8"))
    if len(records)!=1: raise ValueError("COUNT")
    cfg=records[0]["Config"]
    host=records[0]["HostConfig"]
    if host["NetworkMode"]!=network: raise ValueError("NETWORK")
    if not host["ReadonlyRootfs"] or host["Privileged"]: raise ValueError("ROOTFS_OR_PRIVILEGE")
    if cfg["User"]!="65532:65532": raise ValueError("USER")
    if host["PidsLimit"]!=32 or host["Memory"]!=134217728 or host["MemorySwap"]!=134217728:
        raise ValueError("MEMORY_PIDS")
    if host.get("NanoCpus")!=500000000: raise ValueError("CPU")
    if "ALL" not in (host.get("CapDrop") or []): raise ValueError("CAPABILITIES")
    if not any(s.startswith("no-new-privileges") for s in (host.get("SecurityOpt") or [])):
        raise ValueError("PRIVS")
    if host.get("Binds"): raise ValueError("UNEXPECTED_BINDS")
    if cfg.get("Entrypoint")!=["/probe"]: raise ValueError("ENTRYPOINT")
    if any(v.startswith(("GITHUB_","AWS_","AZURE_","GOOGLE_","GH_")) for v in cfg.get("Env") or []):
        raise ValueError("ENV")
    expected={"/input":(str(pathlib.Path(input_path).resolve()),True),
              "/output":(str(pathlib.Path(output_path).resolve()),False)}
    mounts=host.get("Mounts") or []
    if len(mounts)!=2: raise ValueError("MOUNT_COUNT")
    for item in mounts:
        dst=item.get("Target")
        if item.get("Type")!="bind" or dst not in expected: raise ValueError("MOUNT_TARGET")
        source,read_only=expected.pop(dst)
        if str(pathlib.Path(item.get("Source","")).resolve())!=source:
            raise ValueError("MOUNT_SOURCE_MISMATCH")
        if item.get("ReadOnly") is not read_only:
            raise ValueError("MOUNT_READONLY_MISMATCH")
    if expected: raise ValueError("MOUNT_MISSING")

if __name__=="__main__":
    try: verify(*sys.argv[1:])
    except (IndexError,ValueError,KeyError,TypeError,OSError) as e:
        known={"COUNT","NETWORK","ROOTFS_OR_PRIVILEGE","USER","MEMORY_PIDS","CPU","CAPABILITIES","PRIVS","UNEXPECTED_BINDS","ENTRYPOINT","ENV","MOUNT_COUNT","MOUNT_TARGET","MOUNT_SCOPE","MOUNT_SOURCE_MISMATCH","MOUNT_READONLY_MISMATCH","MOUNT_MISSING"}
        reason=str(e) if isinstance(e,ValueError) and str(e) in known else type(e).__name__
        print("PREFLIGHT_SPEC_FAILED:"+reason,file=sys.stderr)
        sys.exit(1)
    print("PREFLIGHT_SPEC_OK")
