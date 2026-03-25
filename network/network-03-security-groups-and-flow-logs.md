# Security Group Hardening & VPC Flow Logs

Security groups are the last layer of network access control before traffic reaches an ePHI resource. VPC Flow Logs are the record of what traffic actually reached (or was rejected by) those controls. Together, they form the enforcement and audit layer for HIPAA's network transmission security requirements.

---

## Security Group Design Principles

**Principle 1 — Default deny.** Security groups are stateful and deny all inbound traffic by default. Never add a rule unless there is a documented, specific business reason for it.

**Principle 2 — Reference security groups, not CIDR blocks, for internal traffic.** Using a security group ID as a source means only resources in that group can communicate — regardless of IP address changes or auto-scaling events.

**Principle 3 — No 0.0.0.0/0 inbound rules except on the public ALB security group.** Every other security group should accept traffic only from specific sources.

**Principle 4 — Port 22 (SSH) and 3389 (RDP) should not exist as inbound rules.** Use AWS Systems Manager Session Manager for administrative access instead.

---

## Security Group Architecture for ePHI Workloads

### ALB Security Group — Public Facing

```bash
# Create ALB security group — accepts HTTPS from internet, HTTP for redirect
ALB_SG=$(aws ec2 create-security-group \
  --group-name hipaa-alb-sg \
  --description "HIPAA ALB - HTTPS inbound only" \
  --vpc-id vpc-YOUR_VPC_ID \
  --tag-specifications 'ResourceType=security-group,Tags=[{Key=Name,Value=hipaa-alb-sg},{Key=HIPAAScope,Value=true}]' \
  --query 'GroupId' --output text)

# Allow HTTPS from anywhere (public-facing ALB)
aws ec2 authorize-security-group-ingress \
  --group-id $ALB_SG \
  --protocol tcp --port 443 --cidr 0.0.0.0/0

# Allow HTTP from anywhere — for 301 redirect only (see 02-tls-enforcement.md)
aws ec2 authorize-security-group-ingress \
  --group-id $ALB_SG \
  --protocol tcp --port 80 --cidr 0.0.0.0/0

# Allow all outbound (ALB needs to reach app tier)
aws ec2 authorize-security-group-egress \
  --group-id $ALB_SG \
  --protocol -1 --port -1 --cidr 0.0.0.0/0
```

### Application Tier Security Group

```bash
# Create app tier security group — accepts traffic only from ALB SG
APP_SG=$(aws ec2 create-security-group \
  --group-name hipaa-app-sg \
  --description "HIPAA App tier - accepts traffic from ALB only" \
  --vpc-id vpc-YOUR_VPC_ID \
  --tag-specifications 'ResourceType=security-group,Tags=[{Key=Name,Value=hipaa-app-sg},{Key=HIPAAScope,Value=true}]' \
  --query 'GroupId' --output text)

# Accept HTTPS from ALB security group only (not from 0.0.0.0/0)
aws ec2 authorize-security-group-ingress \
  --group-id $APP_SG \
  --protocol tcp --port 443 \
  --source-group $ALB_SG

# Outbound to data tier and AWS services (no unrestricted outbound)
aws ec2 authorize-security-group-egress \
  --group-id $APP_SG \
  --protocol tcp --port 5432 \
  --destination-group $DB_SG  # RDS PostgreSQL — reference by SG, not CIDR

aws ec2 authorize-security-group-egress \
  --group-id $APP_SG \
  --protocol tcp --port 443 --cidr 0.0.0.0/0  # For AWS API calls (override with VPC endpoints where possible)
```

### Data Tier Security Group

```bash
# Create data tier security group — accepts traffic only from App SG
DB_SG=$(aws ec2 create-security-group \
  --group-name hipaa-db-sg \
  --description "HIPAA Data tier - accepts traffic from App tier only" \
  --vpc-id vpc-YOUR_VPC_ID \
  --tag-specifications 'ResourceType=security-group,Tags=[{Key=Name,Value=hipaa-db-sg},{Key=HIPAAScope,Value=true}]' \
  --query 'GroupId' --output text)

# MySQL — accept from App SG only
aws ec2 authorize-security-group-ingress \
  --group-id $DB_SG \
  --protocol tcp --port 3306 \
  --source-group $APP_SG

# PostgreSQL — accept from App SG only
aws ec2 authorize-security-group-ingress \
  --group-id $DB_SG \
  --protocol tcp --port 5432 \
  --source-group $APP_SG

# Remove the default outbound rule — data tier should not initiate outbound connections
aws ec2 revoke-security-group-egress \
  --group-id $DB_SG \
  --protocol -1 --port -1 --cidr 0.0.0.0/0
```

---

## Removing Dangerous Default Rules

The default security group in every VPC allows all inbound traffic from members of the same security group. This is often overlooked and should be removed.

```bash
# Get the default security group ID
DEFAULT_SG=$(aws ec2 describe-security-groups \
  --filters Name=group-name,Values=default Name=vpc-id,Values=vpc-YOUR_VPC_ID \
  --query 'SecurityGroups[0].GroupId' --output text)

# Remove default inbound rule (allows all traffic from same SG)
aws ec2 revoke-security-group-ingress \
  --group-id $DEFAULT_SG \
  --source-group $DEFAULT_SG \
  --protocol -1

# Remove default outbound rule
aws ec2 revoke-security-group-egress \
  --group-id $DEFAULT_SG \
  --protocol -1 --port -1 --cidr 0.0.0.0/0
```

> **Best practice:** Tag the default security group as `DoNotUse` and ensure no resources are assigned to it. AWS does not allow you to delete the default security group.

---

## Auditing Security Groups

```bash
# Find security groups with unrestricted inbound access (0.0.0.0/0 or ::/0)
aws ec2 describe-security-groups \
  --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`] && (FromPort==`-1` || FromPort==`22` || FromPort==`3389` || FromPort==`3306` || FromPort==`5432`)]].[GroupId,GroupName,Description]' \
  --output table

# Find security groups with SSH open to the internet
aws ec2 describe-security-groups \
  --query 'SecurityGroups[?IpPermissions[?FromPort==`22` && IpRanges[?CidrIp==`0.0.0.0/0`]]].[GroupId,GroupName]' \
  --output table

# Find security groups with RDP open to the internet
aws ec2 describe-security-groups \
  --query 'SecurityGroups[?IpPermissions[?FromPort==`3389` && IpRanges[?CidrIp==`0.0.0.0/0`]]].[GroupId,GroupName]' \
  --output table

# Find database ports open to the internet
for PORT in 3306 5432 1433 27017; do
  echo "=== Port $PORT ==="
  aws ec2 describe-security-groups \
    --query "SecurityGroups[?IpPermissions[?FromPort==\`$PORT\` && IpRanges[?CidrIp==\`0.0.0.0/0\`]]].[GroupId,GroupName]" \
    --output table
done
```

---

## VPC Flow Logs

VPC Flow Logs record metadata for all IP traffic passing through your VPC — accepted, rejected, and attempted connections. For HIPAA, they serve as the network-layer audit trail that supports §164.312(b) audit controls.

> **Note:** Flow logs capture metadata (source IP, destination IP, port, protocol, action) — not packet payloads. They tell you *that* a connection was made, not *what data was transferred*.

### Enable Flow Logs on the VPC (All Traffic)

```bash
# Create a dedicated S3 bucket for flow logs
aws s3api create-bucket \
  --bucket your-org-vpc-flow-logs \
  --region us-east-1

# Enable flow logs — capture ALL traffic (ACCEPT and REJECT) to S3
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids vpc-YOUR_VPC_ID \
  --traffic-type ALL \
  --log-destination-type s3 \
  --log-destination arn:aws:s3:::your-org-vpc-flow-logs/ \
  --log-format '${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status} ${vpc-id} ${subnet-id} ${instance-id} ${tcp-flags} ${type} ${pkt-srcaddr} ${pkt-dstaddr}'
```

> **Traffic type ALL vs ACCEPT/REJECT:** Capturing `ALL` is required for HIPAA. `ACCEPT`-only logs miss rejected connection attempts, which are often the most security-relevant traffic.

### Enable Flow Logs to CloudWatch (For Real-Time Analysis)

For real-time querying and alerting on flow log data, also route to CloudWatch Logs:

```bash
# Create CloudWatch log group for flow logs
aws logs create-log-group \
  --log-group-name /aws/vpc/flowlogs

aws logs put-retention-policy \
  --log-group-name /aws/vpc/flowlogs \
  --retention-in-days 2557

# Create IAM role for flow logs to write to CloudWatch
aws iam create-role \
  --role-name VPCFlowLogsRole \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "vpc-flow-logs.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

aws iam put-role-policy \
  --role-name VPCFlowLogsRole \
  --policy-name VPCFlowLogsPolicy \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": ["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents","logs:DescribeLogGroups","logs:DescribeLogStreams"],
      "Resource": "*"
    }]
  }'

# Enable flow logs to CloudWatch
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids vpc-YOUR_VPC_ID \
  --traffic-type ALL \
  --log-destination-type cloud-watch-logs \
  --log-group-name /aws/vpc/flowlogs \
  --deliver-logs-permission-arn arn:aws:iam::YOUR_ACCOUNT_ID:role/VPCFlowLogsRole
```

### Querying Flow Logs with CloudWatch Insights

```bash
# Run a query to find rejected connections to your RDS security group
# (Run in CloudWatch Logs Insights console or via CLI)
cat << 'EOF'
fields @timestamp, srcAddr, dstAddr, srcPort, dstPort, action
| filter action = "REJECT"
| filter dstPort in [3306, 5432, 1433]
| sort @timestamp desc
| limit 100
EOF

# Query for connections from unexpected external IPs to app tier
cat << 'EOF'
fields @timestamp, srcAddr, dstAddr, dstPort, action, bytes
| filter action = "ACCEPT"
| filter dstAddr like /^10\.0\.10\./
| filter srcAddr not like /^10\./
| sort bytes desc
| limit 50
EOF
```

---

## Verifying Flow Log Coverage

```bash
# Confirm flow logs are enabled on all VPCs
aws ec2 describe-vpcs --query 'Vpcs[*].VpcId' --output text | \
  tr '\t' '\n' | \
  xargs -I {} sh -c 'echo -n "VPC {}: "; aws ec2 describe-flow-logs --filter Name=resource-id,Values={} --query "FlowLogs[0].FlowLogStatus" --output text'

# List all flow log configurations
aws ec2 describe-flow-logs \
  --query 'FlowLogs[*].[FlowLogId,ResourceId,TrafficType,LogDestinationType,LogDestination,FlowLogStatus]' \
  --output table
```

---

## Common Security Group and Flow Log Failures in Healthcare Environments

| Failure | Why It Matters |
|---|---|
| Security groups using CIDR blocks for internal traffic | IP changes or auto-scaling break access controls silently |
| Port 22/3389 open from 0.0.0.0/0 | Direct administrative access to ePHI systems from the internet |
| Database ports reachable from application subnet via 0.0.0.0/0 | Overly permissive — any compromised app instance can reach any database |
| Default security group with unrestricted inbound | Resources accidentally assigned to default SG are exposed |
| Flow logs set to ACCEPT-only | Rejected connection attempts (reconnaissance, brute force) not captured |
| Flow logs only on CloudWatch, not S3 | No immutable long-term copy; CloudWatch Logs can be deleted |
| VPC flow logs not enabled at all | No network-layer audit trail; HIPAA audit controls not satisfied at the network level |

---

## HIPAA Mapping

| Control | HIPAA Reference |
|---|---|
| Security group least-privilege rules | §164.312(a)(1) — Access Control |
| No direct internet access to ePHI resources | §164.312(e)(1) — Transmission Security |
| VPC Flow Logs capturing all traffic | §164.312(b) — Audit Controls |
| Flow log retention for 6+ years | §164.530(j) — Documentation Retention |
| Rejected connection attempts captured | §164.308(a)(6) — Security Incident Procedures |

---

*Part of the [HIPAA-Cloud-Security-AWS](../README.md) reference repository.*
