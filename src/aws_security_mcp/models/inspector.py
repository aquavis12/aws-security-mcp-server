"""Inspector-specific models."""

from typing import Dict, Any, List, Optional
from datetime import datetime
from pydantic import BaseModel

class InspectorFinding(BaseModel):
    """Inspector finding model."""
    arn: str
    title: str
    description: str
    recommendation: str
    severity: str
    numeric_severity: float
    package_vulnerability_details: Optional[Dict[str, Any]]
    network_reachability_details: Optional[Dict[str, Any]]
    status: str
    remediation_recommendation: Dict[str, Any]
    first_observed_at: datetime
    last_observed_at: datetime
    updated_at: datetime

class InspectorAssessmentRun(BaseModel):
    """Inspector assessment run model."""
    arn: str
    name: str
    assessment_template_arn: str
    state: str
    duration_in_seconds: int
    states_count: Dict[str, int]
    start_time: datetime
    created_at: datetime
    completed_at: Optional[datetime]
    state_changes: List[Dict[str, Any]]
    notifications: List[Dict[str, Any]]

class InspectorAssessmentTemplate(BaseModel):
    """Inspector assessment template model."""
    arn: str
    name: str
    target_arn: str
    duration_in_seconds: int
    rules_package_arns: List[str]
    user_attributes_for_findings: List[Dict[str, str]]
    last_assessment_run_arn: Optional[str]
