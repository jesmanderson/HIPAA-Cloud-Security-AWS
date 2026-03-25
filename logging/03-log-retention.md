# Log Retention Policy — Meeting HIPAA's 6-Year Requirement

HIPAA requires covered entities to retain documentation of their security policies and procedures — including audit logs — for **six years** from the date of creation or the date it was last in effect, whichever is later (45 CFR §164.530(j)).

Most AWS accounts fail this requirement not because they lack logs, but because CloudWatch Logs default to a 90-day retention window and no one changed it.

---

## What HIPAA Actually Requires

The relevant standard is §164.530(j)(2):

> *"A covered entity must retain the documentation required by paragraph (j)(1) of this section for 6 years from the date of its creation or the date when it was last in effect, whichever is later."*

**In practice, this means:**

- Audit logs (CloudTrail, CloudWatch, application access logs) must be retained for 6 years
- Logs must be available for retrieval during an audit or breach investigation
- Logs cannot be altered or deleted during the retention period
- Retention must be documented in your organization's policies

---

## AWS Log Sources That Require 6-Year Retention

| Log Source | Default Retention | Action Required |
|---|---|---|
| CloudTrail (S3) | Indefinite (you pay for storage) | Enable Object Lock; lifecycle to Glacier |
| CloudWatch Logs | Never expires (but costs mount) | Set retention to 2557 days (7 years) |
| S3 Access Logs | Indefinite (you pay for storage) | Enable Object Lock; lifecycle to Glacier |
| VPC Flow Logs | Depends on destination | Route to S3 with Object Lock |
| ALB/ELB Access Logs | Indefinite (you pay for storage) | Enable Object Lock; lifecycle to Glacier |
| RDS Logs | 0–35 days depending on engine | Export to CloudWatch or S3 |

> **Why 7 years in some configurations?** HIPAA requires 6 years from *last in effect*, which may push the practical window past 6 years for policies still active. 2557 days (≈7 years) is a common safe harbor.

---

## CloudWatch Logs — Set Retention Policy

By default, CloudWatch log groups **never expire** — but you're still billed for storage. More importantly, there's no enforcement preventing accidental deletion. Set an explicit retention period:

```bash
# Set retention on your CloudTrail log group
aws logs put-retention-policy \
  --log-group-name "CloudTrail/DefaultLogGroup" \
  --retention-in-days 2557

# Apply to all HIPAA-relevant log groups
for LOG_GROUP in \
  "CloudTrail/DefaultLogGroup" \
  "/aws/vpc/flowlogs" \
  "/aws/rds/instance/your-db-instance/audit"; do
  aws logs put-retention-policy \
    --log-group-name "$LOG_GROUP" \
    --retention-in-days 2557
  echo "Retention set for $LOG_GROUP"
done
```

**Verify:**

```bash
aws logs describe-log-groups \
  --query 'logGroups[*].[logGroupName,retentionInDays]' \
  --output table
```

Any log group showing `None` under retention is a gap.

---

## S3 Log Storage — Object Lock and Lifecycle Configuration

CloudTrail logs delivered to S3 need two things: **immutability** (so they can't be deleted or tampered with) and **lifecycle tiering** (so you're not paying S3 Standard rates for 6-year-old logs).

### Step 1 — Enable Object Lock on Your Log Bucket

Object Lock must be enabled at bucket creation. If your existing log bucket doesn't have it, create a new bucket and point CloudTrail to it.

```bash
# Create a new log bucket with Object Lock enabled
aws s3api create-bucket \
  --bucket your-org-hipaa-logs \
  --region us-east-1 \
  --object-lock-enabled-for-bucket

# Set a default retention rule (COMPLIANCE mode — cannot be overridden even by root)
aws s3api put-object-lock-configuration \
  --bucket your-org-hipaa-logs \
  --object-lock-configuration '{
    "ObjectLockEnabled": "Enabled",
    "Rule": {
      "DefaultRetention": {
        "Mode": "COMPLIANCE",
        "Years": 7
      }
    }
  }'
```

> **GOVERNANCE vs COMPLIANCE mode:**
> - `GOVERNANCE` — users with `s3:BypassGovernanceRetention` permission can delete objects. Useful for testing.
> - `COMPLIANCE` — no user, including root, can delete objects before the retention period expires. Required for HIPAA audit evidence.

### Step 2 — Add a Lifecycle Policy to Tier Logs to Glacier

```bash
aws s3api put-bucket-lifecycle-configuration \
  --bucket your-org-hipaa-logs \
  --lifecycle-configuration '{
    "Rules": [
      {
        "ID": "HIPAA-Log-Retention-Tiering",
        "Status": "Enabled",
        "Filter": { "Prefix": "" },
        "Transitions": [
          {
            "Days": 90,
            "StorageClass": "STANDARD_IA"
          },
          {
            "Days": 365,
            "StorageClass": "GLACIER"
          }
        ]
      }
    ]
  }'
```

**Storage cost impact:** Moving logs to Glacier after 365 days typically reduces log storage costs by 70–80% while maintaining full retrieval capability for audits.

---

## RDS Audit Log Export

RDS logs are frequently overlooked. Database audit logs are often the most relevant evidence in a breach investigation involving ePHI.

```bash
# Enable audit logging on RDS MySQL/Aurora instance
aws rds modify-db-instance \
  --db-instance-identifier your-hipaa-db \
  --cloudwatch-logs-export-configuration '{"EnableLogTypes":["audit","error","general","slowquery"]}' \
  --apply-immediately

# Set retention on the resulting CloudWatch log group
aws logs put-retention-policy \
  --log-group-name "/aws/rds/instance/your-hipaa-db/audit" \
  --retention-in-days 2557
```

---

## VPC Flow Log Export to S3

Routing VPC Flow Logs to S3 (rather than only CloudWatch) gives you a second copy subject to Object Lock protection:

```bash
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids vpc-YOUR_VPC_ID \
  --traffic-type ALL \
  --log-destination-type s3 \
  --log-destination arn:aws:s3:::your-org-hipaa-logs/vpc-flow-logs/
```

---

## Auditing Your Retention Posture

Run this check quarterly or after any infrastructure change:

```bash
# Check all CloudWatch log groups for missing or short retention
aws logs describe-log-groups \
  --query 'logGroups[?retentionInDays < `2557` || retentionInDays == null].[logGroupName, retentionInDays]' \
  --output table

# Confirm Object Lock is active on your log bucket
aws s3api get-object-lock-configuration \
  --bucket your-org-hipaa-logs

# Verify lifecycle rules are in place
aws s3api get-bucket-lifecycle-configuration \
  --bucket your-org-hipaa-logs
```

---

## Documenting Your Retention Policy

HIPAA requires the policy itself to be documented — not just implemented technically. Your written policy should capture:

- Which log sources are in scope
- Retention period (minimum 6 years) and why
- Storage location and access controls
- Who is responsible for retention compliance reviews
- Process for retrieving logs during an audit or breach investigation
- Date the policy was last reviewed

Store this documentation in the same S3 bucket as your logs, also subject to Object Lock. The policy document itself is subject to HIPAA's 6-year retention requirement.

---

## Common Retention Failures in Healthcare Environments

| Failure | Why It Matters |
|---|---|
| CloudWatch log groups left at default (no retention set) | Logs can be manually deleted; no enforcement of 6-year window |
| S3 log bucket without Object Lock | Logs can be deleted or overwritten; inadmissible as audit evidence |
| Object Lock set to GOVERNANCE instead of COMPLIANCE | Privileged users can still delete logs before retention expires |
| Lifecycle policy missing — logs stay in S3 Standard | No technical failure, but unnecessary cost; often leads to manual cleanup that deletes logs early |
| RDS logs not exported | Database access to ePHI goes unretained; critical gap in breach investigations |
| Retention policy not documented in writing | Technical compliance without documentation does not satisfy the HIPAA standard |

---

## HIPAA Mapping

| Control | HIPAA Reference |
|---|---|
| 6-year log retention | §164.530(j) — Documentation Retention |
| Audit log immutability | §164.312(b) — Audit Controls |
| Access log retention for ePHI systems | §164.312(b) — Audit Controls |
| Written retention policy | §164.316(b)(1) — Documentation |

---

*Part of the [HIPAA-Cloud-Security-AWS](../README.md) reference repository.*
