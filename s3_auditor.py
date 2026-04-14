#!/usr/bin/env python3
"""Audit S3 buckets for public exposure and weak hardening.

Usage: python3 s3_auditor.py <buckets.json>
"""
import json
import sys

ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"
AUTH_USERS = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
PAB_KEYS = ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy",
            "RestrictPublicBuckets"]


def load_buckets(path):
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, list):
        return data
    return data.get("Buckets", [data])


def check_public_acl(bucket):
    out = []
    for grant in bucket.get("Acl", {}).get("Grants", []):
        uri = grant.get("Grantee", {}).get("URI", "")
        perm = grant.get("Permission", "?")
        if uri == ALL_USERS:
            out.append(("CRITICAL", f"Public ACL grant to everyone ({perm})"))
        elif uri == AUTH_USERS:
            out.append(("HIGH", f"ACL grant to any AWS account ({perm})"))
    return out


def _principal_is_public(principal):
    if principal == "*":
        return True
    if isinstance(principal, dict):
        aws = principal.get("AWS")
        return aws == "*" or (isinstance(aws, list) and "*" in aws)
    return False


def check_public_policy(bucket):
    out = []
    for stmt in (bucket.get("Policy") or {}).get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        if _principal_is_public(stmt.get("Principal")) and not stmt.get("Condition"):
            out.append(("CRITICAL",
                        f"Bucket policy allows public access (Principal *, {stmt.get('Action', '?')})"))
    return out


def check_public_access_block(bucket):
    pab = bucket.get("PublicAccessBlock")
    if not pab:
        return [("HIGH", "Block Public Access not configured")]
    off = [k for k in PAB_KEYS if not pab.get(k)]
    if off:
        return [("HIGH", f"Block Public Access incomplete: {', '.join(off)} disabled")]
    return []


def check_encryption(bucket):
    if not (bucket.get("Encryption") or {}).get("Rules"):
        return [("MEDIUM", "No default encryption configured")]
    return []


def check_logging(bucket):
    if not (bucket.get("Logging") or {}).get("LoggingEnabled"):
        return [("LOW", "Server access logging disabled")]
    return []


def check_versioning(bucket):
    if (bucket.get("Versioning") or {}).get("Status") != "Enabled":
        return [("LOW", "Versioning not enabled")]
    return []


CHECKS = [
    check_public_acl,
    check_public_policy,
    check_public_access_block,
    check_encryption,
    check_logging,
    check_versioning,
]


def main():
    if len(sys.argv) != 2:
        print("usage: s3_auditor.py <buckets.json>")
        sys.exit(1)
    count = 0
    for bucket in load_buckets(sys.argv[1]):
        name = bucket.get("Name", "?")
        for check in CHECKS:
            for severity, title in check(bucket):
                print(f"[{severity:8}] {name}  {title}")
                count += 1
    print(f"\n{count} finding(s)." if count else "No S3 findings.")


if __name__ == "__main__":
    main()
