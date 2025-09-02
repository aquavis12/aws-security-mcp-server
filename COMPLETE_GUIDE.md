# AWS Security MCP Server - Complete Guide

## Overview
A Model Context Protocol (MCP) server providing 66 AWS security tools across 20 services.

**Status**: ✅ Working with AWS account 183631310514

## Quick Start

### 1. Test Server
```bash
python test_server.py
```

### 2. Run Server
```bash
python -m aws_security_mcp
```

## Integration Setup

### VS Code
1. Install MCP extension
2. Use `.vscode/settings.json` (already configured)
3. Restart VS Code
4. Try Command Palette (Ctrl+Shift+P) → `iam_list_users`

### Amazon Q
1. Install Amazon Q extension
2. Use `amazon_q_config.json` configuration
3. Restart IDE



## Available Tools (66 total)

### ACM (2 tools)
- `acm_list_certificates` - List SSL/TLS certificates
- `acm_describe_certificate` - Get certificate details

### Audit Manager (2 tools)
- `auditmanager_list_assessments` - List assessments
- `auditmanager_list_frameworks` - List frameworks

### CloudWatch (2 tools)
- `cloudwatch_list_metrics` - List CloudWatch metrics
- `cloudwatch_list_alarms` - List CloudWatch alarms

### EC2 Security (4 tools)
- `ec2_describe_security_groups` - List security groups
- `ec2_describe_network_acls` - List network ACLs
- `s3_list_buckets` - List S3 buckets
- `s3_get_bucket_policy` - Get S3 bucket policy

### Identity Center (2 tools)
- `identitycenter_list_instances` - List Identity Center instances
- `identitycenter_list_permission_sets` - List permission sets

### Verified Access (2 tools)
- `verifiedaccess_describe_instances` - List Verified Access instances
- `verifiedaccess_describe_groups` - List Verified Access groups

### VPC Lattice (3 tools)
- `vpclattice_list_services` - List VPC Lattice services
- `vpclattice_list_service_networks` - List service networks
- `vpclattice_get_auth_policy` - Get auth policy

### IAM (5 tools)
- `iam_list_users` - List IAM users
- `iam_list_roles` - List IAM roles
- `iam_list_policies` - List IAM policies
- `iam_get_user` - Get user details
- `iam_get_account_summary` - Get account summary

### KMS (3 tools)
- `kms_list_keys` - List KMS keys
- `kms_describe_key` - Get key details
- `kms_get_key_rotation_status` - Get key rotation status

### GuardDuty (3 tools)
- `guardduty_list_detectors` - List GuardDuty detectors
- `guardduty_list_findings` - List findings
- `guardduty_get_detector` - Get detector details

### Security Hub (3 tools)
- `securityhub_get_findings` - Get Security Hub findings
- `securityhub_get_enabled_standards` - Get enabled standards
- `securityhub_describe_hub` - Get hub configuration

### AWS Config (3 tools)
- `config_describe_config_rules` - List Config rules
- `config_get_compliance_details_by_config_rule` - Get compliance details
- `config_describe_configuration_recorders` - Get configuration recorders

### Access Analyzer (2 tools)
- `accessanalyzer_list_analyzers` - List Access Analyzers
- `accessanalyzer_list_findings` - List findings

### CloudTrail (3 tools)
- `cloudtrail_describe_trails` - List CloudTrail trails
- `cloudtrail_get_trail_status` - Get trail status
- `cloudtrail_lookup_events` - Look up events

### Inspector (2 tools)
- `inspector_list_findings` - List Inspector findings
- `inspector_get_coverage` - Get coverage statistics

### Macie (3 tools)
- `macie_get_findings` - Get Macie findings
- `macie_list_classification_jobs` - List classification jobs
- `macie_get_macie_session` - Get session info

### Network Firewall (3 tools)
- `networkfirewall_list_firewalls` - List firewalls
- `networkfirewall_describe_firewall` - Describe firewall
- `networkfirewall_list_rule_groups` - List rule groups

### Secrets Manager (3 tools)
- `secretsmanager_list_secrets` - List secrets
- `secretsmanager_describe_secret` - Get secret details
- `secretsmanager_get_resource_policy` - Get resource policy

### Shield (4 tools)
- `shield_list_protections` - List Shield protections
- `shield_describe_protection` - Describe protection
- `shield_get_subscription_state` - Get subscription state
- `shield_list_attacks` - List DDoS attacks

### WAF (4 tools)
- `waf_list_web_acls` - List Web ACLs
- `waf_get_web_acl` - Get Web ACL details
- `waf_list_ip_sets` - List IP sets
- `waf_list_rule_groups` - List rule groups

## Configuration Files

- `amazon_q_config.json` - Amazon Q
- `.vscode/settings.json` - VS Code workspace
- `mcp-config.json` - Generic MCP client

## Environment Variables

- `AWS_REGION` - AWS region (default: us-east-1)
- `AWS_PROFILE` - AWS profile (default: default)
- `LOG_LEVEL` - Logging level (default: INFO)

## Next Steps

1. **Test VS Code Integration**
   - Install MCP extension
   - Restart VS Code
   - Try `iam_list_users` in Command Palette

2. **Optional Enhancements**
   - Add more AWS services
   - Create custom workflows
   - Package for distribution

## Troubleshooting

- **Server won't start**: Check AWS credentials
- **No tools visible**: Restart IDE after configuration
- **Permission errors**: Verify AWS IAM permissions

**Server Status**: ✅ Ready and working with 66 tools across 20 AWS services