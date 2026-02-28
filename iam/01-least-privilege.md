# Least Privilege: HIPAA Minimum Necessary Access

## HIPAA Requirement

HIPAA's Access Control standard (§164.312(a)(1)) requires covered 
entities to implement technical policies and procedures that allow 
only authorized persons to access ePHI and only the minimum 
ePHI necessary to do their job.

In AWS, this means no IAM user, role, or service should have access 
to more resources or more actions than their specific job function 
requires.

---

## The Principle in Practice

Most AWS environments violate least privilege in three ways:

**Problem 1 — Wildcard actions on sensitive resources**
```json
{
  "Effect": "Allow",
  "Action": "s3:*",
  "Resource": "arn:aws:s3:::hipaa-patient-data/*"
}
```
This gives full S3 access to a bucket containing ePHI. A developer 
who only needs to read files has just as much access as someone 
who can delete everything.

**The fix — Scope actions to what the role actually needs**
```json
{
  "Effect": "Allow",
  "Action": [
    "s3:GetObject",
    "s3:ListBucket"
  ],
  "Resource": [
    "arn:aws:s3:::hipaa-patient-data",
    "arn:aws:s3:::hipaa-patient-data/*"
  ]
}
```

---

**Problem 2 — Wildcard resources**
```json
{
  "Effect": "Allow",
  "Action": "s3:GetObject",
  "Resource": "*"
}
```
This allows reading objects from every S3 bucket in the account, 
including buckets containing ePHI that this role has no business 
accessing.

**The fix — Scope resources explicitly**
```json
{
  "Effect": "Allow",
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::hipaa-patient-data/*"
}
```

---

**Problem 3 — Attaching AWS managed policies without reviewing scope**
`AmazonS3FullAccess` gives full S3 access across the entire account. 
`AmazonDynamoDBFullAccess` gives full DynamoDB access. These 
AWS-managed policies are convenient but almost always grant far 
more than any individual role needs.

**The fix — Write custom policies scoped to specific resources**

---

## IAM Permission Boundary

A permissions boundary sets the maximum permissions any IAM entity 
can ever have, even if a broader policy is attached. This is 
especially important in healthcare environments where developers 
or admins might accidentally or intentionally escalate their own 
privileges.

Save this as `permissions_boundary.json` and create it in your account:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowCoreServices",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:ListBucket",
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:Query",
        "dynamodb:Scan",
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "cloudwatch:PutMetricData",
        "kms:Decrypt",
        "kms:GenerateDataKey"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyIAMEscalation",
      "Effect": "Deny",
      "Action": [
        "iam:CreateUser",
        "iam:DeleteUser",
        "iam:AttachUserPolicy",
        "iam:PutUserPolicy",
        "iam:CreateAccessKey",
        "iam:UpdateAccessKey",
        "iam:CreateLoginProfile",
        "iam:UpdateLoginProfile",
        "iam:AttachRolePolicy",
        "iam:PutRolePolicy",
        "iam:PassRole"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyBillingAndOrgAccess",
      "Effect": "Deny",
      "Action": [
        "aws-portal:*",
        "organizations:*",
        "account:*"
      ],
      "Resource": "*"
    }
  ]
}
```

Create the boundary in AWS:
```powershell
aws iam create-policy `
  --policy-name hipaa-permissions-boundary `
  --policy-document file://permissions_boundary.json
```

Attach it when creating any new user or role:
```powershell
aws iam create-user `
  --user-name analyst.jane `
  --permissions-boundary arn:aws:iam::<account-id>:policy/hipaa-permissions-boundary
```

---

## Least Privilege Audit Script

Run this to identify IAM users and roles with overly broad permissions. 
Save as `scripts/audit_least_privilege.ps1`:
```powershell
# Audit IAM users and roles for AdministratorAccess or wildcard policies
# HIPAA context: identifies access control gaps under §164.312(a)(1)

Write-Host "`n=== HIPAA IAM Least Privilege Audit ===" -ForegroundColor Cyan
Write-Host "Checking for overprivileged users and roles...`n"

# Check users with AdministratorAccess directly attached
$users = aws iam list-users --query 'Users[*].UserName' --output text
foreach ($user in $users.Split()) {
    $policies = aws iam list-attached-user-policies `
        --user-name $user `
        --query 'AttachedPolicies[*].PolicyName' `
        --output text
    if ($policies -match "AdministratorAccess") {
        Write-Host "⚠️  FINDING: $user has AdministratorAccess attached directly" `
            -ForegroundColor Red
        Write-Host "   Recommendation: Move to an admin role with MFA condition" `
            -ForegroundColor Yellow
    }
}

# Check for users with inline policies (often a sign of ungoverned access)
foreach ($user in $users.Split()) {
    $inline = aws iam list-user-policies `
        --user-name $user `
        --query 'PolicyNames' `
        --output text
    if ($inline -ne "None" -and $inline -ne "") {
        Write-Host "⚠️  FINDING: $user has inline policies: $inline" `
            -ForegroundColor Yellow
        Write-Host "   Recommendation: Convert to managed policies for auditability" `
            -ForegroundColor Yellow
    }
}

Write-Host "`nAudit complete. Review findings above and remediate before next access review." `
    -ForegroundColor Cyan
```

---

## Compliance Evidence to Collect

After implementing these controls, collect the following as audit 
evidence:

- [ ] Screenshot of IAM policies attached to each role — no wildcards 
      on ePHI resources
- [ ] Screenshot showing permissions boundary attached to all users 
      and roles
- [ ] Output from `audit_least_privilege.ps1` — zero critical findings
- [ ] IAM Access Analyzer findings — no unintended external access
- [ ] Date of last access review — should be within 90 days

Store evidence in a dated folder. If HHS OCR investigates a breach, 
documented evidence of regular access reviews and least privilege 
enforcement is a significant mitigating factor in penalty calculations.
