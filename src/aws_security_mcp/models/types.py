"""Type definitions for AWS Security MCP Server."""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel

class Tool(BaseModel):
    """Tool model for MCP server."""
    name: str
    description: str
    inputSchema: Dict[str, Any]

class SecurityFinding(BaseModel):
    """Security finding model."""
    finding_id: str
    title: str
    description: str
    severity: str
    resource_id: str
    resource_type: str
    aws_account_id: str
    region: str
    created_at: str
    updated_at: str
    service_source: str
    status: str
    remediation: Optional[str] = None

class ComplianceResult(BaseModel):
    """Compliance check result model."""
    rule_name: str
    resource_id: str
    resource_type: str
    compliance_status: str
    last_evaluation: str
    rule_type: str

class SecurityAlert(BaseModel):
    """Security alert model."""
    alert_id: str
    title: str
    description: str
    severity: str
    service: str
    status: str
    created_at: str
    affected_resources: List[str]

class SecurityMetric(BaseModel):
    """Security metric model."""
    metric_name: str
    value: float
    unit: str
    timestamp: str
    dimensions: Dict[str, str]

class ResourceConfiguration(BaseModel):
    """Resource security configuration model."""
    resource_id: str
    resource_type: str
    configuration: Dict[str, Any]
    relationships: List[Dict[str, str]]
    tags: Dict[str, str]

class MCPRequest(BaseModel):
    """MCP request model."""
    command: str
    parameters: Dict[str, Any] = {}

class MCPResponse(BaseModel):
    """MCP response model."""
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
