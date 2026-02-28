# Logging: HIPAA Audit Controls

HIPAA's Audit Controls standard (§164.312(b)) requires covered 
entities to implement hardware, software, and procedural mechanisms 
that record and examine activity in information systems that contain 
or use ePHI.

In plain language: if someone accesses, modifies, or deletes ePHI 
in your AWS environment, you need a record of it, and you need to 
actually review that record.

This section covers the AWS services that satisfy this requirement:

| AWS Service | What It Does | HIPAA Purpose |
|-------------|-------------|---------------|
| CloudTrail | Records every API call in your AWS account | Audit trail for all ePHI environment activity |
| CloudWatch Logs | Stores, monitors, and alerts on log data | Real-time activity monitoring |
| CloudWatch Alarms | Triggers alerts on suspicious activity | Incident detection |
| S3 Log Storage | Long-term log retention | HIPAA requires 6-year retention |

---

## Files in This Section

| File | What It Covers |
|------|---------------|
| `01-cloudtrail-setup.md` | CloudTrail configuration for HIPAA audit controls |
| `02-cloudwatch-alerts.md` | CloudWatch alarms for suspicious ePHI activity  |
| `03-log-retention.md` | Log retention policy meeting HIPAA's 6-year requirement |

---

## The Most Common Logging Failures in Healthcare Environments

1. **CloudTrail not enabled in all regions** — attackers target 
   regions where logging is off
2. **CloudTrail logs not protected from deletion** — logs that can 
   be deleted are not reliable audit evidence
3. **No log review process** — enabling logging without reviewing 
   it does not satisfy HIPAA audit controls
4. **Logs retained less than 6 years** — HIPAA requires 6-year 
   retention of documentation including audit logs
5. **Management events only — no data events** — S3 object-level 
   access to ePHI buckets requires data event logging enabled
