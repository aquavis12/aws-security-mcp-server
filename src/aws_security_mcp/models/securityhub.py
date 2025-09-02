"""SecurityHub-specific models."""

from typing import Dict, Any, List, Optional
from datetime import datetime
from pydantic import BaseModel

class SecurityHubFinding(BaseModel):
    """SecurityHub finding model."""
    id: str
    product_arn: str
    generator_id: str
    aws_account_id: str
    types: List[str]
    first_observed_at: datetime
    last_observed_at: datetime
    created_at: datetime
    updated_at: datetime
    severity: Dict[str, Any]
    title: str
    description: str
    remediation: Optional[Dict[str, Any]] = None
    resources: List[Dict[str, Any]]
    compliance: Optional[Dict[str, Any]] = None
    workflow: Dict[str, Any]
    record_state: str

class SecurityHubStandard(BaseModel):
    """SecurityHub security standard model."""
    name: str
    arn: str
    description: str
    enabled_by_default: bool
    standards_status: str
    controls: List[Dict[str, Any]]
