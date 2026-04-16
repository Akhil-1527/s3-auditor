#!/usr/bin/env python3
"""s3-auditor - check AWS S3 buckets for weak security posture.

Stdlib only. Reads a JSON export of bucket settings (ACL, policy, public-access
block, encryption, logging, versioning) and flags public exposure and missing
hardening. Built to run offline against an export you assemble from the
`aws s3api get-bucket-*` calls, so it drops into CI without live credentials.

Examples:
    python3 s3_auditor.py buckets.json
    python3 s3_auditor.py buckets.json --json --min-severity HIGH
"""
import argparse
import json
import sys

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"
AUTH_USERS = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
PAB_KEYS = ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy",
            "RestrictPublicBuckets"]


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
            actions = stmt.get("Action", "?")
            out.append(("CRITICAL",
                        f"Bucket policy allows public access (Principal *, {actions})"))
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
    enc = bucket.get("Encryption") or {}
    if not enc.get("Rules"):
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


def audit(buckets):
    findings = []
    for bucket in buckets:
        name = bucket.get("Name", "?")
        for check in CHECKS:
            for severity, title in check(bucket):
                findings.append({"severity": severity, "bucket": name, "issue": title})
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["bucket"]))
    return findings


def load_buckets(path):
    text = sys.stdin.read() if path == "-" else open(path, encoding="utf-8").read()
    data = json.loads(text)
    if isinstance(data, list):
        return data
    return data.get("Buckets", [data])


def build_parser():
    parser = argparse.ArgumentParser(
        description="Audit S3 bucket security posture (stdlib only)."
    )
    parser.add_argument("path", help="bucket-config JSON file, or '-' for stdin")
    parser.add_argument("--min-severity", choices=list(SEVERITY_ORDER), default="LOW",
                        help="only report at/above this severity (default: LOW)")
    parser.add_argument("--json", action="store_true", help="emit results as JSON")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    floor = SEVERITY_ORDER[args.min_severity]
    findings = [f for f in audit(load_buckets(args.path))
                if SEVERITY_ORDER[f["severity"]] <= floor]
    if args.json:
        print(json.dumps(findings, indent=2))
    elif not findings:
        print("No S3 findings.")
    else:
        for f in findings:
            print(f"[{f['severity']:8}] {f['bucket']}  {f['issue']}")
        print(f"\n{len(findings)} finding(s).")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
