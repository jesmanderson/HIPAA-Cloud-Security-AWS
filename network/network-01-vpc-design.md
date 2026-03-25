# VPC Design for ePHI Workloads

A VPC is the network perimeter for ePHI in AWS. The goal of HIPAA-compliant VPC design is to ensure that systems processing or storing ePHI are isolated from the internet, accessible only to authorized systems, and structured so that a compromise in one layer cannot directly reach another.

---

## Core Design Principles

**Principle 1 — ePHI never touches a public subnet.** RDS instances, application servers processing ePHI, and internal services belong in private subnets. Only load balancers and NAT gateways live in public subnets.

**Principle 2 — Internet access for private resources goes through NAT, not IGW.** Private subnets route outbound traffic through a NAT Gateway. Inbound internet traffic never reaches ePHI resources directly.

**Principle 3 — Subnets are segmented by function, not just by public/private.** A three-tier model (public / application / data) limits lateral movement if a layer is compromised.

**Principle 4 — VPC endpoints replace internet routing for AWS service calls.** S3, KMS, and other AWS API calls from private subnets should use VPC Endpoints rather than routing through NAT to the internet.

---

## Recommended Subnet Architecture

```
VPC: 10.0.0.0/16
│
├── Public Subnets (10.0.1.0/24, 10.0.2.0/24)
│   └── ALB, NAT Gateway, Bastion (if used)
│   └── Internet Gateway attached
│
├── Application Subnets (10.0.10.0/24, 10.0.11.0/24)
│   └── ECS tasks, Lambda (VPC-attached), EC2 app servers
│   └── No direct internet access — outbound via NAT only
│
└── Data Subnets (10.0.20.0/24, 10.0.21.0/24)
    └── RDS instances, ElastiCache, ePHI data stores
    └── No internet access — only accepts traffic from Application subnets
```

Multi-AZ deployment across at least two availability zones is required for any production ePHI workload.

---

## Creating the VPC and Subnets

```bash
# Create the VPC
aws ec2 create-vpc \
  --cidr-block 10.0.0.0/16 \
  --tag-specifications 'ResourceType=vpc,Tags=[{Key=Name,Value=hipaa-prod-vpc},{Key=HIPAAScope,Value=true}]'

VPC_ID=$(aws ec2 describe-vpcs \
  --filters Name=tag:Name,Values=hipaa-prod-vpc \
  --query 'Vpcs[0].VpcId' --output text)

# Enable DNS hostnames (required for some VPC endpoints)
aws ec2 modify-vpc-attribute --vpc-id $VPC_ID --enable-dns-hostnames
aws ec2 modify-vpc-attribute --vpc-id $VPC_ID --enable-dns-support

# Create subnets across two AZs
# Public subnets
aws ec2 create-subnet --vpc-id $VPC_ID --cidr-block 10.0.1.0/24 \
  --availability-zone us-east-1a \
  --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=hipaa-public-1a},{Key=Tier,Value=public}]'

aws ec2 create-subnet --vpc-id $VPC_ID --cidr-block 10.0.2.0/24 \
  --availability-zone us-east-1b \
  --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=hipaa-public-1b},{Key=Tier,Value=public}]'

# Application subnets
aws ec2 create-subnet --vpc-id $VPC_ID --cidr-block 10.0.10.0/24 \
  --availability-zone us-east-1a \
  --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=hipaa-app-1a},{Key=Tier,Value=application}]'

aws ec2 create-subnet --vpc-id $VPC_ID --cidr-block 10.0.11.0/24 \
  --availability-zone us-east-1b \
  --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=hipaa-app-1b},{Key=Tier,Value=application}]'

# Data subnets
aws ec2 create-subnet --vpc-id $VPC_ID --cidr-block 10.0.20.0/24 \
  --availability-zone us-east-1a \
  --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=hipaa-data-1a},{Key=Tier,Value=data}]'

aws ec2 create-subnet --vpc-id $VPC_ID --cidr-block 10.0.21.0/24 \
  --availability-zone us-east-1b \
  --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=hipaa-data-1b},{Key=Tier,Value=data}]'
```

---

## Internet Gateway and NAT Gateway

```bash
# Create and attach Internet Gateway (for public subnets only)
IGW_ID=$(aws ec2 create-internet-gateway \
  --tag-specifications 'ResourceType=internet-gateway,Tags=[{Key=Name,Value=hipaa-igw}]' \
  --query 'InternetGateway.InternetGatewayId' --output text)

aws ec2 attach-internet-gateway --internet-gateway-id $IGW_ID --vpc-id $VPC_ID

# Allocate Elastic IPs and create NAT Gateways (one per AZ for HA)
EIP_1=$(aws ec2 allocate-address --domain vpc --query 'AllocationId' --output text)
EIP_2=$(aws ec2 allocate-address --domain vpc --query 'AllocationId' --output text)

PUBLIC_SUBNET_1A=$(aws ec2 describe-subnets \
  --filters Name=tag:Name,Values=hipaa-public-1a \
  --query 'Subnets[0].SubnetId' --output text)

PUBLIC_SUBNET_1B=$(aws ec2 describe-subnets \
  --filters Name=tag:Name,Values=hipaa-public-1b \
  --query 'Subnets[0].SubnetId' --output text)

NAT_1A=$(aws ec2 create-nat-gateway \
  --subnet-id $PUBLIC_SUBNET_1A \
  --allocation-id $EIP_1 \
  --tag-specifications 'ResourceType=natgateway,Tags=[{Key=Name,Value=hipaa-nat-1a}]' \
  --query 'NatGateway.NatGatewayId' --output text)

NAT_1B=$(aws ec2 create-nat-gateway \
  --subnet-id $PUBLIC_SUBNET_1B \
  --allocation-id $EIP_2 \
  --tag-specifications 'ResourceType=natgateway,Tags=[{Key=Name,Value=hipaa-nat-1b}]' \
  --query 'NatGateway.NatGatewayId' --output text)
```

---

## Route Tables

```bash
# Public route table — routes to IGW
PUBLIC_RT=$(aws ec2 create-route-table --vpc-id $VPC_ID \
  --tag-specifications 'ResourceType=route-table,Tags=[{Key=Name,Value=hipaa-public-rt}]' \
  --query 'RouteTable.RouteTableId' --output text)

aws ec2 create-route --route-table-id $PUBLIC_RT \
  --destination-cidr-block 0.0.0.0/0 --gateway-id $IGW_ID

# Associate public subnets with public route table
aws ec2 associate-route-table --route-table-id $PUBLIC_RT --subnet-id $PUBLIC_SUBNET_1A
aws ec2 associate-route-table --route-table-id $PUBLIC_RT --subnet-id $PUBLIC_SUBNET_1B

# Application route tables — route outbound to NAT (one per AZ)
APP_RT_1A=$(aws ec2 create-route-table --vpc-id $VPC_ID \
  --tag-specifications 'ResourceType=route-table,Tags=[{Key=Name,Value=hipaa-app-rt-1a}]' \
  --query 'RouteTable.RouteTableId' --output text)

aws ec2 create-route --route-table-id $APP_RT_1A \
  --destination-cidr-block 0.0.0.0/0 --nat-gateway-id $NAT_1A

# Data route tables — no internet route at all
DATA_RT=$(aws ec2 create-route-table --vpc-id $VPC_ID \
  --tag-specifications 'ResourceType=route-table,Tags=[{Key=Name,Value=hipaa-data-rt}]' \
  --query 'RouteTable.RouteTableId' --output text)

# No 0.0.0.0/0 route added — data subnets have no internet path
```

---

## VPC Endpoints for AWS Services

Private subnet resources that call AWS APIs (S3, KMS, SSM, etc.) should use VPC Endpoints to avoid routing API calls through NAT to the public internet.

```bash
# S3 Gateway Endpoint (free — no per-hour charge)
aws ec2 create-vpc-endpoint \
  --vpc-id $VPC_ID \
  --service-name com.amazonaws.us-east-1.s3 \
  --vpc-endpoint-type Gateway \
  --route-table-ids $APP_RT_1A $DATA_RT

# KMS Interface Endpoint (required for private subnet encryption operations)
aws ec2 create-vpc-endpoint \
  --vpc-id $VPC_ID \
  --service-name com.amazonaws.us-east-1.kms \
  --vpc-endpoint-type Interface \
  --subnet-ids $APP_SUBNET_1A $APP_SUBNET_1B \
  --security-group-ids sg-YOUR_ENDPOINT_SG \
  --private-dns-enabled

# SSM Interface Endpoint (required if using Systems Manager without bastion)
aws ec2 create-vpc-endpoint \
  --vpc-id $VPC_ID \
  --service-name com.amazonaws.us-east-1.ssm \
  --vpc-endpoint-type Interface \
  --subnet-ids $APP_SUBNET_1A $APP_SUBNET_1B \
  --security-group-ids sg-YOUR_ENDPOINT_SG \
  --private-dns-enabled
```

---

## Verifying VPC Design

```bash
# Confirm no ePHI subnets have direct internet routes
aws ec2 describe-route-tables \
  --filters Name=tag:Tier,Values=data \
  --query 'RouteTables[*].Routes[?DestinationCidrBlock==`0.0.0.0/0`]'
# Expected output: [] (no internet route on data subnets)

# Confirm RDS instances are in private subnets
aws rds describe-db-instances \
  --query 'DBInstances[*].[DBInstanceIdentifier,PubliclyAccessible,DBSubnetGroup.DBSubnetGroupName]' \
  --output table

# List all VPC endpoints
aws ec2 describe-vpc-endpoints \
  --filters Name=vpc-id,Values=$VPC_ID \
  --query 'VpcEndpoints[*].[ServiceName,State,VpcEndpointType]' \
  --output table
```

---

## Common VPC Design Failures in Healthcare Environments

| Failure | Why It Matters |
|---|---|
| RDS instances in public subnets | Database directly reachable from the internet |
| Single NAT Gateway (no HA) | NAT AZ failure takes down all outbound connectivity |
| No VPC Endpoints for S3/KMS | AWS API calls routed through NAT; unnecessary exposure and cost |
| All resources in one subnet | No lateral movement boundary; compromise spreads freely |
| Default VPC used for ePHI workloads | Default VPC has permissive defaults not appropriate for ePHI |
| No multi-AZ deployment | Single AZ failure causes downtime; HIPAA availability standard not met |

---

## HIPAA Mapping

| Control | HIPAA Reference |
|---|---|
| ePHI isolated in private subnets | §164.312(a)(1) — Access Control |
| No direct internet path to data tier | §164.312(e)(1) — Transmission Security |
| Multi-AZ for ePHI availability | §164.312(a)(2)(ii) — Emergency Access Procedure / Availability |
| VPC Endpoints restricting AWS API traffic | §164.312(e)(2)(i) — Transmission Security (integrity controls) |

---

*Part of the [HIPAA-Cloud-Security-AWS](../README.md) reference repository.*
