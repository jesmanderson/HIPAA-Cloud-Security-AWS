# Encryption

HIPAA's Security Rule requires covered entities to implement encryption as a mechanism to protect ePHI — both at rest (§164.312(a)(2)(iv)) and in transit (§164.312(e)(2)(ii)). In AWS, encryption at rest spans every service that stores ePHI: S3 buckets, RDS instances, EBS volumes, and backup vaults.

This section covers the three layers of encryption every HIPAA-covered AWS environment must have configured correctly.

---

## Files in This Section

| File | What It Covers |
|---|---|
| `encryption-01-kms-setup.md` | Customer Managed Key creation, key policies, rotation, and audit |
| `encryption-02-s3-encryption.md` | SSE-KMS enforcement, bucket policies, versioning, and access logging |
| `encryption-03-rds-backup-encryption.md` | RDS encryption at rest, AWS Backup vault encryption, and 6-year retention |

---

## The Most Common Encryption Failures in Healthcare Environments

1. **Using AWS Managed Keys instead of Customer Managed Keys** — AWS Managed Keys cannot be restricted by key policy or audited per-request; you have no control over who can use them
2. **Default S3 encryption without a bucket policy** — encryption is applied by default but not enforced; applications can still upload unencrypted objects if no deny policy exists
3. **RDS instances created without `--storage-encrypted`** — encryption cannot be enabled in-place on an existing RDS instance; it requires a snapshot, copy, and restore
4. **Backup vaults not encrypted with a CMK** — AWS Backup uses an AWS Managed Key by default; backups of ePHI are not under your key policy or audit control
5. **No Vault Lock on backup vaults** — recovery points can be deleted before the 6-year retention window expires, violating HIPAA's documentation retention requirement
6. **Key rotation not enabled** — annual rotation is the industry standard and is expected in HIPAA audits and cyber insurance reviews

---

## How These Controls Connect

KMS is the foundation. Every encryption control in this section depends on a properly configured Customer Managed Key — the S3 bucket policy pins uploads to a specific CMK, RDS encryption references a CMK at creation time, and the Backup vault is encrypted with its own dedicated CMK.

Start with `encryption-01-kms-setup.md` before implementing the other two files.

```
KMS CMK (01)
├── S3 SSE-KMS (02) — enforced via bucket policy
├── RDS storage encryption (03) — set at instance creation
└── AWS Backup vault encryption (03) — set at vault creation
```

---

## HIPAA Mapping

| Control | HIPAA Reference |
|---|---|
| Encryption of ePHI at rest | §164.312(a)(2)(iv) — Encryption and Decryption |
| Customer Managed Key access control | §164.312(a)(1) — Access Control |
| KMS key usage audited via CloudTrail | §164.312(b) — Audit Controls |
| S3 bucket integrity controls | §164.312(c)(1) — Integrity |
| 6-year backup retention with Vault Lock | §164.530(j) — Documentation Retention |

---

*Part of the [HIPAA-Cloud-Security-AWS](../README.md) reference repository.*
