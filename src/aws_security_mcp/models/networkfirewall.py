"""NetworkFirewall-specific models."""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel

class NetworkFirewall(BaseModel):
    """Network Firewall model."""
    firewall_name: str
    firewall_arn: str
    vpc_id: str
    subnet_mappings: List[Dict[str, str]]
    firewall_policy_arn: str
    status: Dict[str, Any]
    description: Optional[str] = None
    tags: Optional[Dict[str, str]] = None

class RuleGroup(BaseModel):
    """Network Firewall rule group model."""
    name: str
    arn: str
    capacity: int
    type: str  # 'STATELESS' or 'STATEFUL'
    description: Optional[str] = None
    rules: Optional[Dict[str, Any]] = None
    tags: Optional[Dict[str, str]] = None

class FirewallPolicy(BaseModel):
    """Network Firewall policy model."""
    policy_name: str
    policy_arn: str
    description: Optional[str] = None
    stateless_default_actions: List[str]
    stateless_fragment_default_actions: List[str]
    stateless_rules: Optional[List[Dict[str, Any]]] = None
    stateful_rules: Optional[List[Dict[str, Any]]] = None
    tags: Optional[Dict[str, str]] = None
