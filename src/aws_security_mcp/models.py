"""Minimal models for AWS Security MCP Server."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel

class BaseResponse(BaseModel):
    """Base response model."""
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

class ListResponse(BaseModel):
    """Generic list response."""
    items: List[Dict[str, Any]] = []
    total: Optional[int] = None
    next_token: Optional[str] = None

class ErrorResponse(BaseModel):
    """Error response."""
    error: str
    service: str