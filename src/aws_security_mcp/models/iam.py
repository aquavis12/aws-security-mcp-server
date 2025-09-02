"""IAM-specific models."""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel

class IAMUser(BaseModel):
    """IAM user model."""
    username: str
    user_id: str
    arn: str
    create_date: str
    path: str
    tags: Optional[Dict[str, str]] = None

class IAMRole(BaseModel):
    """IAM role model."""
    role_name: str
    role_id: str
    arn: str
    create_date: str
    path: str
    assume_role_policy_document: Dict[str, Any]
    description: Optional[str] = None
    max_session_duration: int = 3600
    tags: Optional[Dict[str, str]] = None

class IAMPolicy(BaseModel):
    """IAM policy model."""
    policy_name: str
    policy_id: str
    arn: str
    create_date: str
    update_date: Optional[str] = None
    attachment_count: int = 0
    default_version_id: str = "v1"
    description: Optional[str] = None
    path: str = "/"
    tags: Optional[Dict[str, str]] = None

class IAMListUsersParameters(BaseModel):
    """Parameters for listing IAM users."""
    path_prefix: Optional[str] = None
    marker: Optional[str] = None
    max_items: Optional[int] = None

class IAMListRolesParameters(BaseModel):
    """Parameters for listing IAM roles."""
    path_prefix: Optional[str] = None
    marker: Optional[str] = None
    max_items: Optional[int] = None
