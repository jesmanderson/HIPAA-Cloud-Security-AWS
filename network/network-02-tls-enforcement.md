# TLS Enforcement — ALB & API Gateway

HIPAA's transmission security standard (§164.312(e)(1)) requires that ePHI transmitted over electronic communications networks be protected from unauthorized access. In AWS, this means every path that carries ePHI must enforce TLS — and weak TLS configurations (outdated cipher suites, TLS 1.0/1.1, HTTP fallback) fail the standard as much as no encryption at all.

---

## What Needs TLS Enforcement

| Component | Common Failure | Correct Configuration |
|---|---|---|
| Application Load Balancer (ALB) | HTTP listener left open; TLS 1.0/1.1 permitted | HTTPS only; TLS 1.2+ security policy |
| API Gateway | HTTP endpoint (not HTTPS) | HTTPS enforced; custom domain with ACM cert |
| ALB → backend (target group) | TLS terminated at ALB, HTTP to backend | Enable HTTPS on target group |
| Internal service-to-service | HTTP assumed safe on private network | Mutual TLS or at minimum TLS on all internal paths |

---

## Application Load Balancer — TLS Configuration

### Step 1 — Request a Certificate via ACM

AWS Certificate Manager (ACM) provides free TLS certificates that auto-renew. Never upload a manually managed certificate when ACM is available.

```bash
# Request a public certificate (DNS validation recommended)
aws acm request-certificate \
  --domain-name yourdomain.com \
  --subject-alternative-names "*.yourdomain.com" \
  --validation-method DNS \
  --tags Key=HIPAAScope,Value=true

# ACM returns a CertificateArn — save it
# Complete DNS validation by adding the CNAME record to your DNS provider
# Confirm validation status
aws acm describe-certificate \
  --certificate-arn arn:aws:acm:us-east-1:YOUR_ACCOUNT_ID:certificate/YOUR_CERT_ID \
  --query 'Certificate.[DomainName,Status,NotAfter]'
```

### Step 2 — Create HTTPS Listener on the ALB

```bash
# Create HTTPS listener (port 443) with your ACM certificate
aws elbv2 create-listener \
  --load-balancer-arn arn:aws:elasticloadbalancing:us-east-1:YOUR_ACCOUNT_ID:loadbalancer/app/hipaa-alb/XXXX \
  --protocol HTTPS \
  --port 443 \
  --ssl-policy ELBSecurityPolicy-TLS13-1-2-2021-06 \
  --certificates CertificateArn=arn:aws:acm:us-east-1:YOUR_ACCOUNT_ID:certificate/YOUR_CERT_ID \
  --default-actions Type=forward,TargetGroupArn=arn:aws:elasticloadbalancing:us-east-1:YOUR_ACCOUNT_ID:targetgroup/hipaa-targets/XXXX
```

### Step 3 — Redirect HTTP to HTTPS (Do Not Leave Port 80 Open)

```bash
# Create HTTP listener that redirects to HTTPS — do not leave it forwarding to the backend
aws elbv2 create-listener \
  --load-balancer-arn arn:aws:elasticloadbalancing:us-east-1:YOUR_ACCOUNT_ID:loadbalancer/app/hipaa-alb/XXXX \
  --protocol HTTP \
  --port 80 \
  --default-actions '[{
    "Type": "redirect",
    "RedirectConfig": {
      "Protocol": "HTTPS",
      "Port": "443",
      "StatusCode": "HTTP_301"
    }
  }]'
```

> **Do not simply delete the HTTP listener.** Some clients and health check tools send HTTP. A redirect is better than leaving port 80 closed entirely, which can cause confusing timeout errors.

### Choosing the Right TLS Security Policy

AWS provides named security policies that define which TLS versions and cipher suites the ALB will accept. For HIPAA environments:

| Policy | TLS Versions | Recommendation |
|---|---|---|
| `ELBSecurityPolicy-TLS13-1-2-2021-06` | TLS 1.2, TLS 1.3 | **Recommended** for most HIPAA workloads |
| `ELBSecurityPolicy-TLS13-1-3-2021-06` | TLS 1.3 only | Maximum security; may break older clients |
| `ELBSecurityPolicy-2016-08` | TLS 1.0+ | **Never use** for ePHI workloads |
| `ELBSecurityPolicy-TLS-1-1-2017-01` | TLS 1.1+ | **Avoid** — TLS 1.1 is deprecated |

```bash
# Update security policy on an existing HTTPS listener
aws elbv2 modify-listener \
  --listener-arn arn:aws:elasticloadbalancing:us-east-1:YOUR_ACCOUNT_ID:listener/app/hipaa-alb/XXXX/YYYY \
  --ssl-policy ELBSecurityPolicy-TLS13-1-2-2021-06
```

### Step 4 — Enable TLS on the Target Group (End-to-End Encryption)

TLS termination at the ALB protects the path from client to ALB. For ePHI, the ALB-to-backend path should also be encrypted.

```bash
# Create a target group with HTTPS protocol
aws elbv2 create-target-group \
  --name hipaa-https-targets \
  --protocol HTTPS \
  --port 443 \
  --vpc-id vpc-YOUR_VPC_ID \
  --health-check-protocol HTTPS \
  --health-check-path /health \
  --target-type ip
```

---

## API Gateway — TLS Enforcement

### REST API Gateway

API Gateway HTTPS endpoints are enforced by default for Regional and Edge-Optimized APIs. The risk areas are custom domain configuration and minimum TLS version.

```bash
# Create a custom domain with minimum TLS 1.2
aws apigateway create-domain-name \
  --domain-name api.yourdomain.com \
  --certificate-arn arn:aws:acm:us-east-1:YOUR_ACCOUNT_ID:certificate/YOUR_CERT_ID \
  --security-policy TLS_1_2 \
  --endpoint-configuration types=REGIONAL

# Verify TLS policy on existing custom domain
aws apigateway get-domain-name \
  --domain-name api.yourdomain.com \
  --query '[domainName,securityPolicy,endpointConfiguration]'
```

> **`TLS_1_0` is the API Gateway default for some configurations.** Always explicitly set `TLS_1_2`. The `TLS_1_0` setting permits TLS 1.0 connections, which fails HIPAA transmission security requirements.

### HTTP API Gateway

HTTP APIs (v2) enforce HTTPS automatically. Verify no HTTP-only endpoints exist:

```bash
# List all API Gateway v2 APIs and confirm protocol
aws apigatewayv2 get-apis \
  --query 'Items[*].[Name,ProtocolType,ApiEndpoint]' \
  --output table
```

### Add a Resource Policy to Restrict API Access

For ePHI APIs, a resource policy limits which principals and IP ranges can invoke the API:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "execute-api:Invoke",
      "Resource": "arn:aws:execute-api:us-east-1:YOUR_ACCOUNT_ID:YOUR_API_ID/*",
      "Condition": {
        "NotIpAddress": {
          "aws:SourceIp": [
            "YOUR_ALLOWED_IP_RANGE_1",
            "YOUR_ALLOWED_IP_RANGE_2"
          ]
        }
      }
    },
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "execute-api:Invoke",
      "Resource": "arn:aws:execute-api:us-east-1:YOUR_ACCOUNT_ID:YOUR_API_ID/*"
    }
  ]
}
```

---

## Verifying TLS Configuration

```bash
# Check all ALB listeners for HTTP (non-redirect) or weak TLS policies
aws elbv2 describe-listeners \
  --query 'Listeners[*].[LoadBalancerArn,Port,Protocol,SslPolicy]' \
  --output table

# Flag any listeners on port 80 that are forwarding (not redirecting)
aws elbv2 describe-listeners \
  --query 'Listeners[?Port==`80` && DefaultActions[0].Type==`forward`].[LoadBalancerArn,Port]' \
  --output table

# Verify ACM certificate expiration dates
aws acm list-certificates \
  --query 'CertificateSummaryList[*].[DomainName,CertificateArn,Status]' \
  --output table

# Test TLS version from command line (requires openssl)
openssl s_client -connect yourdomain.com:443 -tls1_1 2>&1 | grep "handshake\|alert"
# Expected: handshake failure (TLS 1.1 should be rejected)

openssl s_client -connect yourdomain.com:443 -tls1_2 2>&1 | grep "Protocol"
# Expected: TLSv1.2 (or TLSv1.3 if using TLS 1.3 only policy)
```

---

## Common TLS Failures in Healthcare Environments

| Failure | Why It Matters |
|---|---|
| HTTP listener forwarding (not redirecting) | Unencrypted ePHI transmission possible if client sends HTTP |
| ALB using `ELBSecurityPolicy-2016-08` | Accepts TLS 1.0 — violates HIPAA transmission security |
| API Gateway custom domain on `TLS_1_0` | Default setting; must be explicitly overridden |
| TLS terminated at ALB, HTTP to backend | ePHI decrypted mid-path and sent in plaintext within the VPC |
| ACM certificate not monitored for expiry | Certificate expiration causes outage and brief TLS failure window |
| Self-signed certificates in production | Not verifiable by clients; often indicates no cert rotation process |

---

## HIPAA Mapping

| Control | HIPAA Reference |
|---|---|
| TLS enforcement on all ePHI transmission paths | §164.312(e)(1) — Transmission Security |
| TLS 1.2+ minimum; deprecated versions rejected | §164.312(e)(2)(ii) — Encryption in Transit |
| HTTPS enforced via ALB redirect, not optional | §164.312(e)(1) — Transmission Security |
| ACM certificate management and auto-renewal | §164.306(a)(1) — Risk Analysis (reducing exposure from expired certs) |

---

*Part of the [HIPAA-Cloud-Security-AWS](../README.md) reference repository.*
