# AWS Security MCP Server

Comprehensive Model Context Protocol (MCP) server for AWS security management with 80+ tools across 21 AWS services.

## What is MCP?

Model Context Protocol enables AI clients to interact with external tools. This creates a bridge between AI assistants and your AWS infrastructure for natural language security management.

### Architecture:
```
AI Client (VS Code/Amazon Q) ←→ MCP Protocol ←→ AWS Security Server ←→ AWS APIs
```

**Benefits:**
- ✅ **Natural Language**: Ask security questions in plain English
- ✅ **Real-time Data**: Direct connection to your AWS account
- ✅ **80+ Security Tools** across 21 AWS services
- ✅ **Performance Optimized**: Fast execution for VS Code/Amazon Q

## Supported Services

**Core Security:** IAM, EC2 Security, S3 Security, KMS, Security Hub, GuardDuty, CloudTrail, Config

**Advanced Security:** Access Analyzer, Inspector, Macie, Network Firewall, Secrets Manager, Shield, WAF, ACM, Audit Manager, CloudWatch, Identity Center, Verified Access, VPC Lattice

**Security Auditing:** Comprehensive audit reports, quick security scans, risk assessment

## Key Features

### Security Capabilities
- 🔍 **Inactive User Detection** (90+ days)
- 🔑 **Access Key Rotation Monitoring** (180+ days)
- 🚫 **Overprivileged Policy Detection**
- 🔒 **MFA Compliance Auditing**
- 🚪 **Open Security Group Detection**
- 📦 **S3 Bucket Security Analysis**
- 📊 **Security Posture Scoring**

### Technical Features
- Async/await implementation
- Comprehensive error handling
- Type-safe Pydantic models
- JSON configuration
- Production-ready architecture

## Quick Start

### Installation
```bash
git clone https://github.com/aquavis12/aws-security-mcp-server.git
cd aws-security-mcp-server
pip install -e .
python -m aws_security_mcp
```

### Prerequisites
- Python 3.9+
- AWS credentials configured
- pip package manager

## Tool Categories (80+ Tools)

#### 🔍 **Identity & Access Management (15 tools)**
- User/role management, inactive user detection, access key rotation, MFA compliance, overprivileged policies

#### 🛡️ **Network Security (11 tools)**
- Security groups, Network ACLs, Network Firewall, VPC Lattice

#### 🔐 **Data Protection (9 tools)**
- S3 bucket security, KMS key management, Secrets Manager, ACM certificates

#### 📊 **Monitoring & Detection (15 tools)**
- GuardDuty, Security Hub, CloudTrail, Inspector, Macie

#### 🛠️ **Infrastructure Security (8 tools)**
- EC2 instances, key pairs, Shield DDoS, WAF

#### 📈 **Compliance & Auditing (22+ tools)**
- Security audit reports, quick scans, Config compliance, Audit Manager

## Example Queries
- "Show me inactive IAM users from the last 90 days"
- "List security groups allowing access from 0.0.0.0/0"
- "Find S3 buckets without encryption"
- "Generate comprehensive security audit report"
- "Run quick security scan for immediate issues"
- "Show users without MFA enabled"
- "Audit access keys not rotated in 6 months"

## VS Code Integration

Add to `settings.json`:
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

## Configuration

Create `mcp-config.json`:
```json
{
    "aws": {
        "region": "us-east-1",
        "profile": "default"
    },
    "logging": {
        "level": "INFO"
    },
    "services": {
        "enabled": [
            "iam", "kms", "guardduty", "securityhub", "config",
            "accessanalyzer", "cloudtrail", "inspector", "macie",
            "networkfirewall", "secretsmanager", "shield", "waf",
            "acm", "auditmanager", "cloudwatch", "ec2_security",
            "identitycenter", "verifiedaccess", "vpclattice", "security_audit"
        ]
    }
}
```

## Project Structure

```
aws-security-mcp-server/
├── src/aws_security_mcp/
│   ├── services/          # 21 AWS service implementations
│   ├── models/           # Pydantic data models
│   ├── utils/            # AWS helper utilities
│   └── server.py         # Main MCP server
├── config/               # Configuration files
├── TOOLS.md             # Complete tools reference
└── pyproject.toml       # Package configuration
```

## Performance

- **Instant Responses**: Sub-second response times
- **Async Architecture**: Efficient concurrent AWS API calls
- **Smart Caching**: Reduces redundant API calls
- **Error Resilience**: Comprehensive error handling

## Documentation

- [TOOLS.md](TOOLS.md) - Complete tools reference
- [SETUP_GUIDE.md](SETUP_GUIDE.md) - Detailed setup guide
- `config/` - Sample configurations

## License

MIT License - see LICENSE file for details