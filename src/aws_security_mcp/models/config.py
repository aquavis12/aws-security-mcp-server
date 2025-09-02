"""AWS Config-specific models."""

from typing import Dict, Any, List, Optional
from datetime import datetime
from pydantic import BaseModel

class ConfigRule(BaseModel):
    """AWS Config rule model."""
    rule_name: str
    rule_arn: str
    rule_id: str
    description: Optional[str]
    scope: Dict[str, Any]
    source: Dict[str, Any]
    input_parameters: Optional[Dict[str, Any]]
    maximum_execution_frequency: Optional[str]
    config_rule_state: str
    created_by: str
    tags: Optional[Dict[str, str]] = None

class ConfigEvaluation(BaseModel):
    """AWS Config evaluation model."""
    config_rule_name: str
    compliance_type: str
    resource_type: str
    resource_id: str
    resource_evaluation_id: str
    time: datetime
    annotation: Optional[str] = None
    ordering_timestamp: datetime

class ConfigRecorder(BaseModel):
    """AWS Config recorder model."""
    name: str
    role_arn: str
    recording_group: Dict[str, Any]
    status: Dict[str, Any]
    last_status: str
    last_error_code: Optional[str] = None
    last_error_message: Optional[str] = None
    last_status_change_time: datetime
