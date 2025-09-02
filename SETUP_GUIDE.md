# AWS Security MCP Server - Complete Setup Guide

## Quick Start

### 1. Installation
```bash
git clone https://github.com/aquavis12/aws-security-mcp-server.git
cd aws-security-mcp-server
pip install -e .
```

### 2. AWS Configuration
Ensure AWS credentials are configured:
```bash
aws configure
# OR set environment variables
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
export AWS_REGION=us-east-1
```

### 3. Test the Server
```bash
python -m aws_security_mcp
```

## VS Code Integration

### Method 1: Direct Configuration
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

### Method 2: Using Configuration File
1. Copy `config/mcp-config.json` to your project root
2. Modify the configuration as needed
3. Reference in VS Code settings

## Amazon Q Integration

Use the provided `config/amazon_q_config.json`:
```json
{
  "mcpServers": {
    "aws-security": {
      "command": "python",
      "args": ["-m", "aws_security_mcp"],
      "env": {
        "AWS_REGION": "us-east-1"
      }
    }
  }
}
```

## Usage Examples

### Natural Language Queries
Once integrated with VS Code or Amazon Q, you can ask:

- "Show me all inactive IAM users from the last 90 days"
- "List security groups that allow access from anywhere"
- "Find S3 buckets without encryption"

- "Show users without MFA enabled"
- "Audit access keys older than 6 months"

### Direct Tool Usage
You can also call tools directly:
```python
# List inactive users
iam_audit_inactive_users(days_inactive=90)

# Audit security groups
ec2_audit_security_groups()

```

## Available Services & Tools

### Core Security Services (78+ tools)
- **IAM** (15 tools) - User management, policy auditing, MFA compliance
- **EC2 Security** (8 tools) - Security groups, instances, key pairs
- **S3 Security** (4 tools) - Bucket policies, encryption, public access
- **KMS** (3 tools) - Key management and rotation
- **GuardDuty** (3 tools) - Threat detection
- **Security Hub** (3 tools) - Centralized findings
- **CloudTrail** (3 tools) - API activity tracking
- **Config** (3 tools) - Compliance monitoring

### Advanced Services
- **Access Analyzer** (2 tools) - Resource access analysis
- **Inspector** (2 tools) - Vulnerability assessments
- **Macie** (3 tools) - Data classification
- **Network Firewall** (3 tools) - Network protection
- **Secrets Manager** (3 tools) - Secret management
- **Shield** (4 tools) - DDoS protection
- **WAF** (4 tools) - Web application firewall
- **ACM** (2 tools) - Certificate management
- **Audit Manager** (2 tools) - Compliance auditing
- **CloudWatch** (2 tools) - Monitoring and alarms
- **Identity Center** (2 tools) - SSO management
- **Verified Access** (2 tools) - Zero trust access
- **VPC Lattice** (3 tools) - Service connectivity


## Configuration Options

### Environment Variables
```bash
export AWS_REGION=us-east-1
export AWS_PROFILE=default
export LOG_LEVEL=INFO
```

### Configuration File (mcp-config.json)
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
            "iam", "kms", "guardduty", "securityhub", "config",
            "accessanalyzer", "cloudtrail", "inspector", "macie",
            "networkfirewall", "secretsmanager", "shield", "waf",
            "acm", "auditmanager", "cloudwatch", "ec2_security",
            "identitycenter", "verifiedaccess", "vpclattice"
        ]
    }
}
```

## Troubleshooting

### Common Issues

#### 1. AWS Credentials Not Found
```bash
# Configure AWS CLI
aws configure

# Or set environment variables
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
```

#### 2. Permission Denied Errors
Ensure your AWS user/role has the necessary permissions:
- IAM read permissions
- EC2 describe permissions
- S3 read permissions
- Security service read permissions

#### 3. Region Issues
Set the correct AWS region:
```bash
export AWS_REGION=us-east-1
```

#### 4. VS Code Integration Issues
- Restart VS Code after configuration changes
- Check the MCP extension is installed and enabled
- Verify the Python path in configuration

### Performance Optimization

The server is optimized for fast responses:
- Async/await implementation
- Efficient AWS API usage
- Smart error handling
- Instant response for audit tools

### Logging

Enable debug logging for troubleshooting:
```bash
export LOG_LEVEL=DEBUG
python -m aws_security_mcp
```

## Security Best Practices

### AWS Permissions
Use least-privilege IAM policies:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:List*",
                "iam:Get*",
                "ec2:Describe*",
                "s3:List*",
                "s3:Get*",
                "kms:List*",
                "kms:Describe*",
                "guardduty:List*",
                "guardduty:Get*",
                "securityhub:Get*",
                "config:Describe*",
                "cloudtrail:Describe*",
                "cloudtrail:LookupEvents"
            ],
            "Resource": "*"
        }
    ]
}
```

### Network Security
- Run the server in a secure environment
- Use VPC endpoints for AWS API calls when possible
- Monitor server logs for unusual activity

## Support

For issues and questions:
1. Check the [TOOLS.md](TOOLS.md) for complete tool reference
2. Review logs for error details
3. Ensure AWS permissions are correctly configured
4. Verify VS Code/Amazon Q integration settings