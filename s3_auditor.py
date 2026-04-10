#!/usr/bin/env python3
"""Check S3 buckets for public ACL grants.

Usage: python3 s3_auditor.py <buckets.json>
"""
import json
import sys

ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"
AUTH_USERS = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"


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
            out.append(f"public ACL grant to everyone ({perm})")
        elif uri == AUTH_USERS:
            out.append(f"ACL grant to any AWS account ({perm})")
    return out


def main():
    if len(sys.argv) != 2:
        print("usage: s3_auditor.py <buckets.json>")
        sys.exit(1)
    count = 0
    for bucket in load_buckets(sys.argv[1]):
        for issue in check_public_acl(bucket):
            print(f"{bucket.get('Name', '?')}: {issue}")
            count += 1
    print(f"\n{count} finding(s)." if count else "No public ACLs found.")


if __name__ == "__main__":
    main()
