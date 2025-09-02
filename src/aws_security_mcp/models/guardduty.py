"""GuardDuty-specific models."""

from typing import Dict, Any, List, Optional
from datetime import datetime
from pydantic import BaseModel

class GuardDutyFinding(BaseModel):
    """GuardDuty finding model."""
    id: str
    arn: str
    detector_id: str
    schema_version: str
    type: str
    resource_type: str
    service: Dict[str, Any]
    severity: float
    created_at: datetime
    updated_at: datetime
    title: str
    description: str
    account_id: str
    region: str
    partition: str
    resource: Dict[str, Any]

class GuardDutyDetector(BaseModel):
    """GuardDuty detector model."""
    id: str
    status: str
    service_role: str
    created_at: datetime
    updated_at: datetime
    data_sources: Dict[str, Any]
    features: List[Dict[str, Any]]
    tags: Optional[Dict[str, str]] = None
