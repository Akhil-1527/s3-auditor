# s3-auditor

A dependency-free S3 bucket security checker. Standard library only. Give it a
JSON export of bucket settings and it flags public exposure and missing
hardening — public ACLs, public bucket policies, gaps in Block Public Access,
no default encryption, no logging, no versioning — ranked by severity.

## Why

Leaky S3 buckets are a perennial breach headline. The checks aren't complicated;
the value is having them in one auditable, CI-able pass instead of clicking
through the console bucket by bucket. It runs against an **export**, so it needs
no live credentials and slots straight into a pipeline.

## Input

Assemble a JSON file (or pipe one in) describing each bucket. Each bucket mirrors
the shapes returned by the `aws s3api get-bucket-*` calls:

```json
{ "Buckets": [
  {
    "Name": "my-bucket",
    "PublicAccessBlock": {"BlockPublicAcls": true, "IgnorePublicAcls": true,
                          "BlockPublicPolicy": true, "RestrictPublicBuckets": true},
    "Acl": {"Grants": []},
    "Policy": {"Statement": []},
    "Encryption": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]},
    "Logging": {"LoggingEnabled": {"TargetBucket": "logs"}},
    "Versioning": {"Status": "Enabled"}
  }
] }
```

## Usage

```bash
python3 s3_auditor.py buckets.json
python3 s3_auditor.py buckets.json --json --min-severity HIGH
cat buckets.json | python3 s3_auditor.py -
```

## What it checks

| Check | Severity |
|-------|----------|
| Public ACL grant (`AllUsers`) | CRITICAL |
| Bucket policy with `Principal: *` and no condition | CRITICAL |
| ACL grant to `AuthenticatedUsers` (any AWS account) | HIGH |
| Block Public Access missing or incomplete | HIGH |
| No default encryption | MEDIUM |
| Server access logging disabled | LOW |
| Versioning not enabled | LOW |

Exit status is `1` when anything is found, so it can gate a pipeline.

## Notes

This audits the bucket *configuration* you give it; it doesn't crawl object ACLs
or evaluate IAM that might grant access by another path. Pair it with
[aws-iam-privesc-finder](https://github.com/Akhil-1527/aws-iam-privesc-finder)
for the identity side of the same question.
