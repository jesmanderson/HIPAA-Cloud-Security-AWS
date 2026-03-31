# Network Security

HIPAA's transmission security standard (§164.312(e)(1)) requires that ePHI transmitted over electronic communications networks be protected from unauthorized access. In AWS, this means the network architecture itself must prevent ePHI from being reachable from the internet, all transmission paths must enforce TLS, and every accepted and rejected connection must be logged.

This section covers the three layers of network security every HIPAA-covered AWS environment must have in place.

---

## Files in This Section

| File | What It Covers |
|---|---|
| `network-01-vpc-design.md` | Three-tier subnet architecture, NAT Gateway, and VPC Endpoints for AWS services |
| `network-02-tls-enforcement.md` | ALB HTTPS configuration, TLS security policy selection, and API Gateway TLS enforcement |
| `network-03-security-groups-and-flow-logs.md` | Least-privilege security group rules, default SG hardening, and VPC Flow Log setup |

---

## The Most Common Network Security Failures in Healthcare Environments

1. **RDS instances deployed in public subnets** — database directly reachable from the internet; the most critical misconfiguration in healthcare AWS environments
2. **Default VPC used for ePHI workloads** — the default VPC has permissive defaults not appropriate for ePHI and no network segmentation between tiers
3. **ALB using a legacy TLS security policy** — policies like `ELBSecurityPolicy-2016-08` permit TLS 1.0, which fails HIPAA's transmission security requirement
4. **HTTP listener forwarding instead of redirecting** — leaves an unencrypted path open; clients sending HTTP reach the backend without TLS
5. **Security groups using CIDR blocks for internal traffic** — IP-based rules break silently during auto-scaling or IP changes; security group references are the correct approach
6. **VPC Flow Logs set to ACCEPT-only or not enabled at all** — rejected connection attempts (reconnaissance, brute force) are not captured; network-layer audit trail is incomplete or missing

---

## How These Controls Connect

VPC design is the foundation. TLS enforcement and security group rules only matter if the underlying network architecture correctly isolates ePHI resources from the internet. A properly configured ALB with TLS 1.2+ is ineffective if the RDS instance it proxies is also sitting in a public subnet with port 3306 open.

Work through the files in order:

```
VPC Design (01) — isolate ePHI from the internet
├── TLS Enforcement (02) — encrypt all transmission paths
└── Security Groups & Flow Logs (03) — control and audit traffic at the resource level
```

---

## HIPAA Mapping

| Control | HIPAA Reference |
|---|---|
| ePHI isolated in private subnets, no internet route | §164.312(e)(1) — Transmission Security |
| TLS 1.2+ enforced on all ePHI transmission paths | §164.312(e)(2)(ii) — Encryption in Transit |
| Least-privilege security group rules | §164.312(a)(1) — Access Control |
| VPC Flow Logs capturing all traffic | §164.312(b) — Audit Controls |
| Flow log retention for 6+ years | §164.530(j) — Documentation Retention |
| Rejected connection attempts captured | §164.308(a)(6) — Security Incident Procedures |

---

*Part of the [HIPAA-Cloud-Security-AWS](../README.md) reference repository.*
