#!/usr/bin/env python3
"""Strict, nonproduction verifier for the one-shot inert Gitleaks report."""
import json
import pathlib
import stat
import sys

LIMIT=65536
EXPECTED_RULE="sar-pilot-inert-rule"
ALLOWED_FILE_NAMES={"positive.txt","/input/positive.txt","input/positive.txt"}

def _unique(pairs):
    output={}
    for k,v in pairs:
        if k in output:
            raise ValueError("DUPLICATE_JSON_KEY")
        output[k]=v
    return output

def inspect_bytes(data):
    if not data or len(data)>LIMIT:
        raise ValueError("MISSING_OR_EXCESSIVE_REPORT")
    try:
        result=json.loads(data.decode("utf-8"),object_pairs_hook=_unique)
    except (UnicodeDecodeError,json.JSONDecodeError) as e:
        raise ValueError("INVALID_JSON") from None
    if not isinstance(result,list) or len(result)!=1:
        raise ValueError("NOT_ONE_FINDING")
    item=result[0]
    if not isinstance(item,dict):
        raise ValueError("INVALID_FINDING")
    if item.get("RuleID")!=EXPECTED_RULE:
        raise ValueError("WRONG_RULE")
    if item.get("File") not in ALLOWED_FILE_NAMES:
        raise ValueError("UNEXPECTED_FILE")
    if any(type(item.get(key)) is not int or item[key]!=expected for key,expected in
           (("StartLine",1),("EndLine",1),("StartColumn",1),("EndColumn",23))):
        raise ValueError("INVALID_LOCATION")
    if item.get("Secret")!="REDACTED" or item.get("Match")!="REDACTED":
        raise ValueError("INVALID_REDACTION")
    fingerprint=item.get("Fingerprint")
    if item.get("Commit", "") != "" or fingerprint != f"{item['File']}:{EXPECTED_RULE}:1":
        raise ValueError("INVALID_FINGERPRINT")
    return {"status":"EXPECTED_INERT_FINDING_OBSERVED","synthetic_only":True,
            "native_report_authenticated":False,"coverage_verified":False,
            "operational_pass":False,"findings":1}

def inspect_path(path):
    p=pathlib.Path(path)
    s=p.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_size>LIMIT:
        raise ValueError("INVALID_REPORT_FILE")
    return inspect_bytes(p.read_bytes())

if __name__=="__main__":
    try:
        if len(sys.argv)!=2: raise ValueError("USAGE")
        receipt=inspect_path(sys.argv[1])
    except (OSError,TypeError,ValueError,RecursionError) as e:
        print("PILOT_REPORT_REJECTED:"+type(e).__name__,file=sys.stderr)
        sys.exit(1)
    print(json.dumps(receipt,sort_keys=True,separators=(",",":")))
