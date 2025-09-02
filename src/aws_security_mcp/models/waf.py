"""WAF-specific models."""

from typing import Dict, Any, List, Optional
from datetime import datetime
from pydantic import BaseModel

class WAFWebACL(BaseModel):
    """WAF Web ACL model."""
    id: str
    name: str
    arn: str
    description: Optional[str]
    default_action: Dict[str, Any]
    rules: List[Dict[str, Any]]
    visibility_config: Dict[str, Any]
    capacity: int
    label_namespace: str
    tags: Optional[Dict[str, str]] = None

class WAFRuleGroup(BaseModel):
    """WAF rule group model."""
    id: str
    name: str
    arn: str
    description: Optional[str]
    capacity: int
    rules: List[Dict[str, Any]]
    visibility_config: Dict[str, Any]
    tags: Optional[Dict[str, str]] = None

class WAFIPSet(BaseModel):
    """WAF IP set model."""
    id: str
    name: str
    arn: str
    description: Optional[str]
    ip_address_version: str
    addresses: List[str]
    tags: Optional[Dict[str, str]] = None
