"""KMS-specific models."""

from typing import Dict, Any, List, Optional
from datetime import datetime
from pydantic import BaseModel

class KMSKey(BaseModel):
    """KMS key model."""
    key_id: str
    arn: str
    alias: Optional[str]
    description: Optional[str]
    enabled: bool
    key_state: str
    creation_date: datetime
    deletion_date: Optional[datetime]
    valid_to: Optional[datetime]
    origin: str
    key_manager: str
    customer_master_key_spec: str
    key_usage: str
    encryption_algorithms: Optional[List[str]] = None
    signing_algorithms: Optional[List[str]] = None
    tags: Optional[Dict[str, str]] = None

class KeyPolicy(BaseModel):
    """KMS key policy model."""
    key_id: str
    policy: Dict[str, Any]
    policy_name: str

class KeyRotation(BaseModel):
    """KMS key rotation model."""
    key_id: str
    enabled: bool
    rotation_interval: Optional[int] = None
    last_rotation_date: Optional[datetime] = None
