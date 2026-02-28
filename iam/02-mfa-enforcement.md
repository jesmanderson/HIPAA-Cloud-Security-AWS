# MFA Enforcement: HIPAA Person Authentication

## HIPAA Requirement

HIPAA's Person Authentication standard (§164.312(d)) requires 
covered entities to implement procedures to verify that a person 
seeking access to ePHI is who they claim to be.

MFA is the most effective technical control for meeting this 
requirement. A username and password alone is not sufficient 
authentication for any account that can access ePHI.

---

## Who Needs MFA

In a HIPAA-covered AWS environment, MFA is required for:

| Account Type | MFA Required | Notes |
|-------------|-------------|-------|
| Root account | Yes — always | Enable immediately, then lock the root account |
| IAM admin users | Yes — always | Any account that can modify IAM needs MFA |
| IAM users accessing ePHI | Yes — always | Any account that can reach patient data |
| IAM users with console access | Yes — always | Console access without MFA is a critical gap |
| Service roles (Lambda, EC2) | No | Service roles use temporary credentials, not MFA |
| CI/CD pipeline roles | No | Use IAM roles with short-lived credentials instead |

---

## Step 1 — Enable MFA on the Root Account

Do this first, before anything else. Root account compromise is 
a catastrophic event in any AWS environment.

1. Sign in to the AWS Console as root
2. Navigate to IAM → Security recommendations
3. Click "Add MFA for root user"
4. Use a hardware MFA device or virtual MFA app, not SMS
5. Store the MFA device and root credentials in a secure location 
   separate from each other

> After enabling root MFA, create a break-glass procedure: 
> document where the root credentials and MFA device are stored, 
> who is authorized to use them, and under what circumstances. 
> This is part of your HIPAA emergency access procedure requirement.

---

## Step 2 — Create the Deny Without MFA Policy

This policy denies all AWS actions to any IAM user who has not 
authenticated with MFA, except the actions needed to set up MFA 
in the first place.

Save as `iam/policies/deny_without_mfa.json`:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowMFASetup",
      "Effect": "Allow",
      "Action": [
        "iam:CreateVirtualMFADevice",
        "iam:EnableMFADevice",
        "iam:ListMFADevices",
        "iam:ListVirtualMFADevices",
        "iam:ResyncMFADevice",
        "iam:DeleteVirtualMFADevice",
        "iam:GetUser",
        "sts:GetCallerIdentity",
        "sts:GetSessionToken",
        "iam:ChangePassword"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyAllWithoutMFA",
      "Effect": "Deny",
      "NotAction": [
        "iam:CreateVirtualMFADevice",
        "iam:EnableMFADevice",
        "iam:ListMFADevices",
        "iam:ListVirtualMFADevices",
        "iam:ResyncMFADevice",
        "iam:DeleteVirtualMFADevice",
        "iam:GetUser",
        "sts:GetCallerIdentity",
        "sts:GetSessionToken",
        "iam:ChangePassword"
      ],
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {
          "aws:MultiFactorAuthPresent": "false"
        }
      }
    }
  ]
}
```

Create and attach the policy:
```powershell
# Create the policy
aws iam create-policy `
  --policy-name hipaa-deny-without-mfa `
  --policy-document file://iam/policies/deny_without_mfa.json

# Create a group for all human users
aws iam create-group --group-name hipaa-human-users

# Attach the MFA enforcement policy to the group
aws iam attach-group-policy `
  --group-name hipaa-human-users `
  --policy-arn arn:aws:iam::<account-id>:policy/hipaa-deny-without-mfa

# Add a user to the group
aws iam add-user-to-group `
  --group-name hipaa-human-users `
  --user-name <username>
```

---

## Step 3 — Audit MFA Coverage

Run this script to identify every IAM user without MFA enabled. 
Save as `scripts/audit_mfa.ps1`:
```powershell
# Audit MFA coverage across all IAM users
# HIPAA context: Person Authentication §164.312(d)
# Run monthly and save output as compliance evidence

Write-Host "`n=== HIPAA MFA Coverage Audit ===" -ForegroundColor Cyan
Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm')`n"

$report = @()
$users = aws iam list-users | ConvertFrom-Json

foreach ($user in $users.Users) {
    $mfaDevices = aws iam list-mfa-devices `
        --user-name $user.UserName | ConvertFrom-Json
    
    $hasMFA = $mfaDevices.MFADevices.Count -gt 0
    $status  = if ($hasMFA) { "COMPLIANT" } else { "GAP — NO MFA" }
    $color   = if ($hasMFA) { "Green" } else { "Red" }
    
    Write-Host "$($user.UserName): $status" -ForegroundColor $color
    
    $report += [PSCustomObject]@{
        Username    = $user.UserName
        MFAEnabled  = $hasMFA
        Status      = $status
        AuditDate   = Get-Date -Format 'yyyy-MM-dd'
    }
}

# Save report as CSV for compliance evidence
$reportPath = ".\reports\mfa_audit_$(Get-Date -Format 'yyyyMMdd').csv"
$report | Export-Csv -Path $reportPath -NoTypeInformation

Write-Host "`nReport saved: $reportPath" -ForegroundColor Cyan
Write-Host "File this report as HIPAA audit evidence under §164.312(d)" `
    -ForegroundColor Yellow

# Summary
$gaps = $report | Where-Object { -not $_.MFAEnabled }
if ($gaps.Count -eq 0) {
    Write-Host "`n✅ All users have MFA enabled — compliant" -ForegroundColor Green
} else {
    Write-Host "`n⚠️  $($gaps.Count) user(s) without MFA — remediate immediately" `
        -ForegroundColor Red
    $gaps | ForEach-Object { 
        Write-Host "   - $($_.Username)" -ForegroundColor Red 
    }
}
```

---

## Compliance Evidence to Collect

- [ ] Screenshot of root account MFA enabled in IAM Security 
      recommendations
- [ ] Screenshot of `hipaa-deny-without-mfa` policy attached to 
      `hipaa-human-users` group
- [ ] CSV output from `audit_mfa.ps1` — all users showing COMPLIANT
- [ ] Date of last MFA audit — run this monthly and keep every report
- [ ] Break-glass procedure document — where root credentials and 
      MFA device are stored and who is authorized to use them
