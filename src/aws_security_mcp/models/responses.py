"""Common response models for MCP server."""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

@dataclass
class ErrorResponse:
    """Error response model."""
    error: str
    details: Optional[Dict[str, Any]] = None

@dataclass
class ListResponse:
    """List response model."""
    items: List[Dict[str, Any]]
    next_token: Optional[str] = None

@dataclass
class MCPResponse:
    """Base MCP response model."""
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
