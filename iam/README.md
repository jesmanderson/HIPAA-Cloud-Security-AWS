# IAM: Access Control and Person Authentication

HIPAA Technical Safeguards require covered entities to implement 
technical policies and procedures that allow only authorized persons 
to access electronic Protected Health Information (ePHI).

This section covers three HIPAA requirements that live in AWS IAM:

| Requirement | HIPAA Standard | Specification |
|-------------|---------------|---------------|
| Unique user identification | §164.312(a)(1) | Required |
| Person authentication | §164.312(d) | Required |
| Minimum necessary access | §164.312(a)(1) | Addressable |
| Automatic logoff | §164.312(a)(2)(iii) | Addressable |

---

## Files in This Section

| File | What It Covers |
|------|---------------|
| `01-least-privilege.md` | Role-based access design and minimum necessary configurations |
| `02-mfa-enforcement.md` | MFA enforcement policy for all users accessing ePHI environments |
| `03-role-based-access.md` | IAM role structure for common healthcare cloud roles |

---

## The Most Common IAM Failures in Healthcare Environments

Before implementing the configurations in this section, audit your 
current IAM environment for these findings, they appear in nearly 
every healthcare AWS environment:

1. **Root account used for routine operations** — root should never 
   be used after initial account setup
2. **IAM users with AdministratorAccess attached directly** — 
   admin access should only exist in a tightly controlled role
3. **No MFA on any IAM users** — any account without MFA that can 
   reach ePHI is a critical finding
4. **Access keys that have never been rotated** — stale keys are 
   compromised keys waiting to be discovered
5. **Overprivileged service roles** — Lambda functions, EC2 instances, 
   and ECS tasks with wildcard permissions on S3 buckets containing ePHI
6. **No IAM access reviews** — HIPAA requires periodic review of 
   who has access to what

If any of these exist in your environment, start here before 
implementing new configurations. Fixing existing gaps is more 
important than adding new controls on top of a broken foundation.

## Watch

[![AWS IAM for HIPAA Compliance – Full Walkthrough](https://img.youtube.com/vi/GOMpEgBRjH4/maxresdefault.jpg)](https://youtu.be/GOMpEgBRjH4)

**[AWS IAM for HIPAA Compliance – Full Walkthrough](https://youtu.be/GOMpEgBRjH4)**
