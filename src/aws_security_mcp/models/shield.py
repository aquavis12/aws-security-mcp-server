"""Shield-specific models."""

from typing import Dict, Any, List, Optional
from datetime import datetime
from pydantic import BaseModel

class ShieldProtection(BaseModel):
    """Shield protection model."""
    id: str
    name: str
    resource_arn: str
    protection_arn: str
    application_layer_automatic_response: Optional[Dict[str, Any]]
    health_check_ids: Optional[List[str]]
    tags: Optional[Dict[str, str]] = None

class ShieldAttack(BaseModel):
    """Shield attack model."""
    id: str
    resource_arn: str
    sub_type: str
    start_time: datetime
    end_time: Optional[datetime]
    attack_counters: List[Dict[str, Any]]
    mitigations: List[Dict[str, Any]]
    attack_properties: Dict[str, Any]

class ShieldSubscription(BaseModel):
    """Shield subscription model."""
    start_time: datetime
    time_commitment_in_seconds: int
    auto_renew: bool
    limits: Dict[str, Any]
    subscription_limits: Dict[str, Any]
    subscription_arn: str
