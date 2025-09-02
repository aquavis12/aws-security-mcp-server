"""Macie-specific models."""

from typing import Dict, Any, List, Optional
from datetime import datetime
from pydantic import BaseModel

class MacieClassificationJob(BaseModel):
    """Macie classification job model."""
    job_id: str
    job_arn: str
    name: str
    status: str
    job_type: str
    created_at: datetime
    updated_at: datetime
    bucket_definitions: List[Dict[str, Any]]
    sampling_percentage: int
    statistics: Optional[Dict[str, Any]] = None
    tags: Optional[Dict[str, str]] = None

class MacieFinding(BaseModel):
    """Macie finding model."""
    id: str
    account_id: str
    region: str
    type: str
    title: str
    description: str
    severity: Dict[str, Any]
    created_at: datetime
    updated_at: datetime
    resources: List[Dict[str, Any]]
    sample_data: Optional[Dict[str, Any]] = None
    category: str
    count: int
    partition: str
    schema_version: str

class SensitiveData(BaseModel):
    """Sensitive data model."""
    category: str
    type: str
    count: int
    occurrences: Dict[str, Any]
    total_count: int
