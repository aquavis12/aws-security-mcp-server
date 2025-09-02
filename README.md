# AWS Security MCP Server

A Model Context Protocol (MCP) server implementation for managing AWS security services. This server provides a unified interface to interact with various AWS security services.

## Supported Services

- IAM Access Analyzer
- CloudTrail
- Config
- GuardDuty
- IAM
- Inspector
- KMS
- Macie
- Network Firewall
- Secrets Manager
- Security Hub
- Shield
- WAF

## Features

- Async/await implementation for efficient request handling
- Comprehensive error handling and logging
- Support for multiple AWS security services
- Easy configuration through JSON config file
- Type-safe implementation using Pydantic models
- Extensive command support for each service

## Getting Started

### Prerequisites

- Python 3.9 or higher
- AWS credentials configured (via AWS CLI, environment variables, or IAM roles)
- pip package manager

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/aws-security-mcp-server.git
cd aws-security-mcp-server

# Install the package and dependencies
pip install -e .
```

### Quick Test

```bash
# Test the server
python test_server.py

# Run the server directly
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

## Available Tools

The server provides tools for the following AWS security services:

### IAM (Identity and Access Management)
- `iam_list_users` - List IAM users
- `iam_list_roles` - List IAM roles  
- `iam_list_policies` - List IAM policies
- `iam_get_user` - Get user details
- `iam_get_account_summary` - Get account summary

### KMS (Key Management Service)
- `kms_list_keys` - List KMS keys
- `kms_describe_key` - Get key details
- `kms_get_key_rotation_status` - Get key rotation status

### GuardDuty
- `guardduty_list_detectors` - List GuardDuty detectors
- `guardduty_list_findings` - List findings
- `guardduty_get_detector` - Get detector details

### Security Hub
- `securityhub_get_findings` - Get Security Hub findings
- `securityhub_get_enabled_standards` - Get enabled standards
- `securityhub_describe_hub` - Get hub configuration

### AWS Config
- `config_describe_config_rules` - List Config rules
- `config_get_compliance_details_by_config_rule` - Get compliance details
- `config_describe_configuration_recorders` - Get configuration recorders

### Access Analyzer
- `accessanalyzer_list_analyzers` - List Access Analyzers
- `accessanalyzer_list_findings` - List findings

### CloudTrail
- `cloudtrail_describe_trails` - List CloudTrail trails
- `cloudtrail_get_trail_status` - Get trail status
- `cloudtrail_lookup_events` - Look up events

### Inspector
- `inspector_list_findings` - List Inspector findings
- `inspector_get_coverage` - Get coverage statistics

### Macie
- `macie_get_findings` - Get Macie findings
- `macie_list_classification_jobs` - List classification jobs
- `macie_get_macie_session` - Get session info

### Network Firewall
- `networkfirewall_list_firewalls` - List firewalls
- `networkfirewall_describe_firewall` - Describe firewall
- `networkfirewall_list_rule_groups` - List rule groups

### Secrets Manager
- `secretsmanager_list_secrets` - List secrets
- `secretsmanager_describe_secret` - Get secret details
- `secretsmanager_get_resource_policy` - Get resource policy

### Shield
- `shield_list_protections` - List Shield protections
- `shield_describe_protection` - Describe protection
- `shield_get_subscription_state` - Get subscription state
- `shield_list_attacks` - List DDoS attacks

### WAF
- `waf_list_web_acls` - List Web ACLs
- `waf_get_web_acl` - Get Web ACL details
- `waf_list_ip_sets` - List IP sets
- `waf_list_rule_groups` - List rule groups

## Development

### Running Tests

```bash
# Run tests with coverage
pytest --cov=aws_security_mcp tests/

# Run type checks
mypy src/aws_security_mcp

# Run linting
flake8 src/aws_security_mcp
black src/aws_security_mcp
isort src/aws_security_mcp
```

### Project Structure

```
aws-security-mcp-server/
├── src/
│   └── aws_security_mcp/
│       ├── __init__.py
│       ├── server.py
│       ├── models.py
│       └── services/
│           ├── __init__.py
│           ├── base.py
│           ├── accessanalyzer.py
│           ├── cloudtrail.py
│           ├── config.py
│           └── ...
├── tests/
├── mcp-config.json
├── requirements.txt
├── setup.py
└── README.md
```

## License

MIT License - see LICENSE file for details
