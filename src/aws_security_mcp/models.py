"""Pydantic models for AWS Security MCP Server."""

from typing import Any, Dict, List, Optional, Union
from datetime import datetime
from pydantic import BaseModel, Field


# IAM Models
class IAMUser(BaseModel):
    user_name: str
    user_id: str
    arn: str
    path: str
    create_date: datetime
    password_last_used: Optional[datetime] = None


class IAMRole(BaseModel):
    role_name: str
    role_id: str
    arn: str
    path: str
    create_date: datetime
    assume_role_policy_document: Optional[str] = None


class IAMPolicy(BaseModel):
    policy_name: str
    policy_id: str
    arn: str
    path: str
    default_version_id: str
    attachment_count: int
    permissions_boundary_usage_count: int
    is_attachable: bool
    description: Optional[str] = None
    create_date: datetime
    update_date: datetime


# KMS Models
class KMSKey(BaseModel):
    key_id: str
    key_arn: str
    alias: Optional[str] = None
    description: Optional[str] = None
    key_usage: str
    key_spec: str
    key_state: str
    origin: str
    key_manager: str
    creation_date: datetime
    enabled: bool
    key_rotation_enabled: Optional[bool] = None


class KMSGrant(BaseModel):
    key_id: str
    grant_id: str
    name: Optional[str] = None
    creation_date: datetime
    grantee_principal: str
    retiring_principal: Optional[str] = None
    operations: List[str]
    constraints: Optional[Dict[str, Any]] = None


# ACM Models
class Certificate(BaseModel):
    certificate_arn: str
    domain_name: str
    subject_alternative_names: List[str] = Field(default_factory=list)
    domain_validation_options: List[Dict[str, Any]] = Field(default_factory=list)
    status: str
    type: str
    key_algorithm: str
    signature_algorithm: str
    in_use_by: List[str] = Field(default_factory=list)
    failure_reason: Optional[str] = None
    issued_at: Optional[datetime] = None
    imported_at: Optional[datetime] = None
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    renewal_eligibility: Optional[str] = None


# Inspector Models
class InspectorFinding(BaseModel):
    finding_arn: str
    aws_account_id: str
    type: str
    description: str
    severity: str
    first_observed_at: datetime
    last_observed_at: datetime
    updated_at: datetime
    status: str
    title: str
    remediation: Optional[Dict[str, Any]] = None
    resources: List[Dict[str, Any]] = Field(default_factory=list)


# GuardDuty Models
class GuardDutyFinding(BaseModel):
    account_id: str
    arn: str
    created_at: str
    description: str
    id: str
    partition: str
    region: str
    resource: Dict[str, Any]
    schema_version: str
    service: Dict[str, Any]
    severity: float
    title: str
    type: str
    updated_at: str


class GuardDutyDetector(BaseModel):
    detector_id: str
    created_at: str
    finding_publishing_frequency: str
    service_role: str
    status: str
    updated_at: str
    data_sources: Optional[Dict[str, Any]] = None
    tags: Optional[Dict[str, str]] = None


# Security Hub Models
class SecurityHubFinding(BaseModel):
    schema_version: str
    id: str
    product_arn: str
    generator_id: str
    aws_account_id: str
    types: List[str]
    first_observed_at: str
    last_observed_at: str
    created_at: str
    updated_at: str
    severity: Dict[str, Any]
    confidence: Optional[int] = None
    criticality: Optional[int] = None
    title: str
    description: str
    remediation: Optional[Dict[str, Any]] = None
    source_url: Optional[str] = None
    product_fields: Dict[str, str] = Field(default_factory=dict)
    user_defined_fields: Dict[str, str] = Field(default_factory=dict)
    malware: List[Dict[str, Any]] = Field(default_factory=list)
    network: Optional[Dict[str, Any]] = None
    network_path: List[Dict[str, Any]] = Field(default_factory=list)
    process: Optional[Dict[str, Any]] = None
    threats: List[Dict[str, Any]] = Field(default_factory=list)
    threat_intel_indicators: List[Dict[str, Any]] = Field(default_factory=list)
    resources: List[Dict[str, Any]]
    compliance: Optional[Dict[str, Any]] = None
    verification_state: str
    workflow_state: str
    workflow: Optional[Dict[str, Any]] = None
    record_state: str


# Network Firewall Models
class NetworkFirewallRule(BaseModel):
    rule_group_arn: str
    rule_group_name: str
    rule_group_id: str
    description: Optional[str] = None
    type: str
    capacity: int
    rule_group_status: str
    tags: Optional[Dict[str, str]] = None
    consumed_capacity: Optional[int] = None
    number_of_associations: Optional[int] = None


class NetworkFirewallPolicy(BaseModel):
    firewall_policy_name: str
    firewall_policy_arn: str
    firewall_policy_id: str
    description: Optional[str] = None
    firewall_policy_status: str
    tags: Optional[Dict[str, str]] = None
    consumed_capacity: Optional[int] = None
    number_of_associations: Optional[int] = None


# WAF Models
class WAFWebACL(BaseModel):
    name: str
    id: str
    arn: str
    description: Optional[str] = None
    default_action: Dict[str, Any]
    rules: List[Dict[str, Any]] = Field(default_factory=list)
    visibility_config: Dict[str, Any]
    capacity: int
    managed_by_firewall_manager: Optional[bool] = None
    label_namespace: Optional[str] = None
    custom_response_bodies: Optional[Dict[str, Any]] = None
    captcha_config: Optional[Dict[str, Any]] = None
    challenge_config: Optional[Dict[str, Any]] = None
    token_domains: List[str] = Field(default_factory=list)


class WAFRuleGroup(BaseModel):
    name: str
    id: str
    arn: str
    description: Optional[str] = None
    capacity: int
    available_labels: List[Dict[str, Any]] = Field(default_factory=list)
    consumed_labels: List[Dict[str, Any]] = Field(default_factory=list)
    label_namespace: Optional[str] = None
    custom_response_bodies: Optional[Dict[str, Any]] = None


# EC2 Security Models
class SecurityGroup(BaseModel):
    group_id: str
    group_name: str
    description: str
    owner_id: str
    vpc_id: Optional[str] = None
    ip_permissions: List[Dict[str, Any]] = Field(default_factory=list)
    ip_permissions_egress: List[Dict[str, Any]] = Field(default_factory=list)
    tags: List[Dict[str, str]] = Field(default_factory=list)


class NetworkAcl(BaseModel):
    network_acl_id: str
    vpc_id: str
    owner_id: str
    entries: List[Dict[str, Any]] = Field(default_factory=list)
    associations: List[Dict[str, Any]] = Field(default_factory=list)
    tags: List[Dict[str, str]] = Field(default_factory=list)
    is_default: bool


# Generic Response Models
class ListResponse(BaseModel):
    items: List[Dict[str, Any]]
    next_token: Optional[str] = None
    total_count: Optional[int] = None


class ErrorResponse(BaseModel):
    error: str
    message: str
    service: str
    operation: str


# Tool Parameter Models
class ListParametersBase(BaseModel):
    max_items: Optional[int] = Field(default=50, le=1000)
    next_token: Optional[str] = None


class IAMListUsersParameters(ListParametersBase):
    path_prefix: Optional[str] = None
    marker: Optional[str] = None


class IAMListRolesParameters(ListParametersBase):
    path_prefix: Optional[str] = None
    marker: Optional[str] = None


class KMSListKeysParameters(ListParametersBase):
    pass


class GuardDutyGetFindingsParameters(BaseModel):
    detector_id: str
    finding_ids: List[str]


class SecurityHubGetFindingsParameters(BaseModel):
    filters: Optional[Dict[str, Any]] = None
    sort_criteria: Optional[List[Dict[str, Any]]] = None
    next_token: Optional[str] = None
    max_results: Optional[int] = Field(default=100, le=100)


class EC2DescribeSecurityGroupsParameters(BaseModel):
    group_ids: Optional[List[str]] = None
    group_names: Optional[List[str]] = None
    filters: Optional[List[Dict[str, Any]]] = None
    dry_run: bool = False
    max_results: Optional[int] = Field(default=1000, le=1000)
    next_token: Optional[str] = None
