# AWS Security MCP Server - Complete Tools Reference

This document lists all 80+ security tools available in the AWS Security MCP Server.

## IAM (Identity and Access Management) - 15 Tools

### Basic IAM Operations
- `iam_list_users` - List IAM users in the account
- `iam_list_roles` - List IAM roles in the account
- `iam_list_policies` - List IAM policies in the account
- `iam_get_user` - Get details for a specific IAM user
- `iam_get_role` - Get details for a specific IAM role
- `iam_get_policy` - Get IAM policy details including document
- `iam_get_account_summary` - Get IAM account summary with usage statistics

### Policy and Permission Management
- `iam_list_attached_user_policies` - List policies attached to a specific user
- `iam_list_attached_role_policies` - List policies attached to a specific role

### Security Auditing
- `iam_get_credential_report` - Get IAM credential report (raw or parsed)
- `iam_audit_inactive_users` - Audit IAM users inactive for specified days (default: 90)
- `iam_audit_unrotated_keys` - Find access keys not rotated for specified days (default: 180)
- `iam_audit_overprivileged_policies` - Identify overprivileged IAM policies
- `iam_audit_mfa_status` - Audit MFA status for all users
- `iam_get_users_not_accessed` - Get users not accessed for specified days

## EC2 Security - 8 Tools

### Security Groups and Network ACLs
- `ec2_describe_security_groups` - List EC2 security groups
- `ec2_describe_network_acls` - List EC2 network ACLs
- `ec2_audit_security_groups` - Audit security groups for risky configurations

### Instance Security
- `ec2_describe_instances` - List EC2 instances with security details
- `ec2_audit_key_pairs` - Audit EC2 key pairs and their usage

### S3 Security (via EC2 Security Service)
- `s3_list_buckets` - List S3 buckets
- `s3_get_bucket_policy` - Get S3 bucket policy
- `s3_get_bucket_encryption` - Get S3 bucket encryption configuration
- `s3_get_bucket_public_access_block` - Get S3 bucket public access block configuration

## KMS (Key Management Service) - 3 Tools
- `kms_list_keys` - List KMS keys
- `kms_describe_key` - Get key details
- `kms_get_key_rotation_status` - Get key rotation status

## GuardDuty - 3 Tools
- `guardduty_list_detectors` - List GuardDuty detectors
- `guardduty_list_findings` - List GuardDuty findings
- `guardduty_get_detector` - Get detector details

## Security Hub - 3 Tools
- `securityhub_get_findings` - Get Security Hub findings
- `securityhub_get_enabled_standards` - Get enabled standards
- `securityhub_describe_hub` - Get hub configuration

## AWS Config - 3 Tools
- `config_describe_config_rules` - List Config rules
- `config_get_compliance_details_by_config_rule` - Get compliance details
- `config_describe_configuration_recorders` - Get configuration recorders

## Access Analyzer - 2 Tools
- `accessanalyzer_list_analyzers` - List Access Analyzers
- `accessanalyzer_list_findings` - List Access Analyzer findings

## CloudTrail - 3 Tools
- `cloudtrail_describe_trails` - List CloudTrail trails
- `cloudtrail_get_trail_status` - Get trail status
- `cloudtrail_lookup_events` - Look up CloudTrail events

## Inspector - 2 Tools
- `inspector_list_findings` - List Inspector findings
- `inspector_get_coverage` - Get Inspector coverage statistics

## Macie - 3 Tools
- `macie_get_findings` - Get Macie findings
- `macie_list_classification_jobs` - List classification jobs
- `macie_get_macie_session` - Get Macie session info

## Network Firewall - 3 Tools
- `networkfirewall_list_firewalls` - List Network Firewalls
- `networkfirewall_describe_firewall` - Describe firewall configuration
- `networkfirewall_list_rule_groups` - List firewall rule groups

## Secrets Manager - 3 Tools
- `secretsmanager_list_secrets` - List secrets
- `secretsmanager_describe_secret` - Get secret details
- `secretsmanager_get_resource_policy` - Get secret resource policy

## Shield - 4 Tools
- `shield_list_protections` - List Shield protections
- `shield_describe_protection` - Describe protection details
- `shield_get_subscription_state` - Get Shield subscription state
- `shield_list_attacks` - List DDoS attacks

## WAF - 4 Tools
- `waf_list_web_acls` - List Web ACLs
- `waf_get_web_acl` - Get Web ACL details
- `waf_list_ip_sets` - List IP sets
- `waf_list_rule_groups` - List WAF rule groups

## ACM (Certificate Manager) - 2 Tools
- `acm_list_certificates` - List SSL/TLS certificates
- `acm_describe_certificate` - Get certificate details

## Audit Manager - 2 Tools
- `auditmanager_list_assessments` - List Audit Manager assessments
- `auditmanager_list_frameworks` - List Audit Manager frameworks

## CloudWatch - 2 Tools
- `cloudwatch_list_metrics` - List CloudWatch metrics
- `cloudwatch_list_alarms` - List CloudWatch alarms

## Identity Center - 2 Tools
- `identitycenter_list_instances` - List Identity Center instances
- `identitycenter_list_permission_sets` - List permission sets

## Verified Access - 2 Tools
- `verifiedaccess_describe_instances` - List Verified Access instances
- `verifiedaccess_describe_groups` - List Verified Access groups

## VPC Lattice - 3 Tools
- `vpclattice_list_services` - List VPC Lattice services
- `vpclattice_list_service_networks` - List service networks
- `vpclattice_get_auth_policy` - Get VPC Lattice auth policy

## Security Audit (Comprehensive Reporting) - 2 Tools
- `security_audit_generate_report` - Generate comprehensive security audit report with executive summary
- `security_audit_quick_scan` - Quick security scan for immediate issue detection

## Tool Categories by Use Case

### 🔍 **Security Auditing & Compliance**
- Comprehensive security audit reports with executive summaries
- Quick security scans for immediate issue detection
- IAM audit tools (inactive users, unrotated keys, MFA status)
- Security group auditing
- S3 bucket security analysis
- Config compliance monitoring
- CloudTrail event analysis

### 🛡️ **Identity & Access Management**
- User and role management
- Policy analysis and attachment
- Credential reporting
- MFA compliance checking
- Overprivileged policy detection

### 🌐 **Network Security**
- Security group analysis
- Network ACL management
- Network Firewall configuration
- VPC Lattice service security

### 🔐 **Data Protection**
- S3 bucket security (encryption, public access)
- KMS key management and rotation
- Secrets Manager integration
- Certificate management (ACM)

### 📊 **Monitoring & Detection**
- GuardDuty threat detection
- Security Hub findings
- CloudTrail event analysis
- Inspector vulnerability assessments
- Macie data classification

### 🛠️ **Infrastructure Security**
- EC2 instance security analysis
- Key pair auditing
- Shield DDoS protection
- WAF web application security

## Usage Examples

### Natural Language Queries (via MCP)
- "Show me all inactive IAM users from the last 90 days"
- "List security groups that allow access from 0.0.0.0/0"

- "Find all S3 buckets without encryption"
- "Generate a comprehensive security audit report"
- "Run a quick security scan for immediate issues"
- "Show users without MFA enabled"

### Direct Tool Calls
```json
{
  "tool": "iam_audit_inactive_users",
  "arguments": {"days_inactive": 90}
}
```

## Total Tool Count: 80+ Tools
- **21 AWS Services** covered
- **Comprehensive security coverage** across all major AWS security domains
- **Real-time auditing** capabilities
- **Executive reporting** with risk scoring
- **Natural language interface** via MCP protocol