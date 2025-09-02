# AWS Security MCP Server

A comprehensive Model Context Protocol (MCP) server implementation for AWS security management, auditing, and compliance monitoring across 21 AWS services with 80+ specialized security tools.

## What is MCP?

Model Context Protocol (MCP) is a standardized communication protocol that enables AI clients to interact with external tools and data sources. This creates a bridge between AI assistants and your AWS infrastructure for natural language security management.

### MCP Architecture:
```
AI Client (VS Code/Amazon Q) ←→ MCP Protocol ←→ AWS Security Server ←→ AWS APIs (boto3)
```

**How it works:**
1. **AI Client** asks: "Show me inactive IAM users from the last 90 days"
2. **MCP Protocol** translates to standardized tool call
3. **AWS Security Server** receives request, calls AWS APIs via boto3
4. **AWS APIs** return security data with risk analysis
5. **Server** formats response with security insights
6. **AI Client** displays actionable security recommendations

**Benefits:**
- ✅ **Standardized Interface**: AI clients automatically discover your AWS security tools
- ✅ **Natural Language**: Ask security questions in plain English
- ✅ **Real-time Data**: Direct connection to your AWS account with instant responses
- ✅ **Security Focus**: 78+ specialized security audit tools across 21 AWS services
- ✅ **Performance Optimized**: Fast execution designed for VS Code and Amazon Q integration

## Supported Services

### Core Security Services
- **IAM** - Identity and Access Management with advanced auditing
- **EC2 Security** - Security Groups, NACLs, Key Pairs, Instance Security
- **S3 Security** - Bucket policies, encryption, public access auditing
- **KMS** - Key Management and rotation monitoring
- **Security Hub** - Centralized security findings
- **GuardDuty** - Threat detection and monitoring
- **CloudTrail** - API activity and security event tracking
- **Config** - Configuration compliance monitoring

### Advanced Security Services
- **IAM Access Analyzer** - Resource access analysis
- **Inspector** - Vulnerability assessments
- **Macie** - Data classification and protection
- **Network Firewall** - Network traffic filtering
- **Secrets Manager** - Secrets rotation and management
- **Shield** - DDoS protection monitoring
- **WAF** - Web application firewall management
- **ACM** - SSL/TLS certificate management
- **Audit Manager** - Compliance auditing
- **CloudWatch** - Security metrics and alarms
- **Identity Center** - SSO and identity management
- **Verified Access** - Zero trust network access
- **VPC Lattice** - Service-to-service connectivity



## Features

### Core Capabilities
- ✅ **78+ Security Tools** across 21 AWS services
- ✅ **Real-time Security Auditing** with risk scoring
- ✅ **Compliance Monitoring** for security best practices
- ✅ **Automated Reporting** with executive summaries
- ✅ **Natural Language Interface** via MCP protocol

### Advanced Security Features
- 🔍 **Inactive User Detection** (90+ days)
- 🔑 **Access Key Rotation Monitoring** (180+ days)
- 🚫 **Overprivileged Policy Detection**
- 🔒 **MFA Compliance Auditing**
- 🚪 **Open Security Group Detection**
- 📦 **S3 Bucket Security Analysis**
- 📊 **Security Posture Scoring**
- 📈 **Trend Analysis and Reporting**

### Technical Features
- Async/await implementation for efficient request handling
- Comprehensive error handling and logging
- Type-safe implementation using Pydantic models
- Easy configuration through JSON config files
- Production-ready architecture

## Getting Started

### Prerequisites

- Python 3.9 or higher
- AWS credentials configured (via AWS CLI, environment variables, or IAM roles)
- pip package manager

### Installation

```bash
# Clone the repository
git clone https://github.com/aquavis12/aws-security-mcp-server.git
cd aws-security-mcp-server

# Install the package and dependencies
pip install -e .

# Run the server
python -m aws_security_mcp
```

### Configuration

Create a `mcp-config.json` file in your project directory:

```json
{
    "server": {
        "host": "localhost",
        "port": 3000
    },
    "aws": {
        "region": "us-east-1",
        "profile": "default",
        "assume_role_arn": null
    },
    "logging": {
        "level": "INFO",
        "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        "file": "aws_security_mcp.log"
    },
    "services": {
        "enabled": [
            "accessanalyzer",
            "cloudtrail",
            "config",
            "guardduty",
            "iam",
            "inspector",
            "kms",
            "macie",
            "networkfirewall",
            "secretsmanager",
            "securityhub",
            "shield",
            "waf"
        ]
    }
}
```

## Complete Tool Reference

The server provides **78+ security tools** across **21 AWS services**. For the complete list, see [TOOLS.md](TOOLS.md).

### Key Security Categories

#### 🔍 **Identity & Access Management (15 tools)**
- User and role management with advanced auditing
- Inactive user detection (90+ days)
- Access key rotation monitoring (180+ days)
- MFA compliance auditing
- Overprivileged policy detection

#### 🛡️ **Network Security (11 tools)**
- Security group analysis and auditing
- Network ACL management
- Network Firewall configuration
- VPC Lattice service security

#### 🔐 **Data Protection (9 tools)**
- S3 bucket security (encryption, public access)
- KMS key management and rotation
- Secrets Manager integration
- Certificate management (ACM)

#### 📊 **Monitoring & Detection (15 tools)**
- GuardDuty threat detection
- Security Hub findings
- CloudTrail event analysis
- Inspector vulnerability assessments
- Macie data classification

#### 🛠️ **Infrastructure Security (8 tools)**
- EC2 instance security analysis
- Key pair auditing
- Shield DDoS protection
- WAF web application security

#### 📈 **Compliance & Auditing (20+ tools)**
- Config compliance monitoring
- Audit Manager assessments
- CloudTrail event analysis
- Security Hub findings

### Example Natural Language Queries
- "Show me all inactive IAM users from the last 90 days"
- "List security groups that allow access from 0.0.0.0/0"

- "Find all S3 buckets without encryption"
- "Show users without MFA enabled"
- "Audit access keys that haven't been rotated in 6 months"



## VS Code & Amazon Q Integration

### VS Code Setup
Add to your VS Code `settings.json`:
```json
{
  "mcp.servers": {
    "aws-security": {
      "command": "python",
      "args": ["-m", "aws_security_mcp"],
      "env": {
        "AWS_REGION": "us-east-1",
        "AWS_PROFILE": "default"
      }
    }
  }
}
```

### Amazon Q Configuration
Use the provided `config/amazon_q_config.json` for Amazon Q integration.

## Project Structure

```
aws-security-mcp-server/
├── src/aws_security_mcp/           # Main package
│   ├── services/                   # 21 AWS service implementations
│   │   ├── iam.py                 # IAM with 15 security tools
│   │   ├── ec2_security.py        # EC2 & S3 security tools

│   │   └── ...                    # Other AWS services
│   ├── models/                    # Pydantic data models
│   ├── utils/                     # AWS helper utilities
│   └── server.py                  # Main MCP server
├── config/                        # Configuration files
│   ├── mcp-config.json           # Server configuration
│   └── amazon_q_config.json      # Amazon Q integration
├── TOOLS.md                       # Complete tools reference
├── COMPLETE_GUIDE.md              # Comprehensive setup guide
└── pyproject.toml                 # Package configuration
```

## Performance & Optimization

- **Instant Responses**: Optimized for VS Code integration with sub-second response times
- **Async Architecture**: Efficient handling of concurrent AWS API calls
- **Smart Caching**: Reduces redundant AWS API calls
- **Error Resilience**: Comprehensive error handling and graceful degradation

## License

MIT License - see LICENSE file for details
