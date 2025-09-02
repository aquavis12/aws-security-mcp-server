"""Audit Manager service implementation for AWS Security MCP Server."""

import logging
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError
import mcp.types as types

logger = logging.getLogger(__name__)


class AuditManagerService:
    """Service for handling Audit Manager operations."""

    def __init__(self, session: boto3.Session):
        """Initialize the Audit Manager service."""
        self.client = session.client("auditmanager")

    def get_tools(self) -> List[types.Tool]:
        """Get available Audit Manager tools."""
        return [
            types.Tool(
                name="auditmanager_list_assessments",
                description="List Audit Manager assessments",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "status": {
                            "type": "string",
                            "enum": ["ACTIVE", "INACTIVE"],
                            "description": "Filter by assessment status"
                        },
                        "max_results": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 100,
                            "default": 50
                        }
                    }
                }
            ),
            types.Tool(
                name="auditmanager_list_frameworks",
                description="List Audit Manager frameworks",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "framework_type": {
                            "type": "string",
                            "enum": ["Standard", "Custom"],
                            "description": "Type of framework"
                        },
                        "max_results": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 100,
                            "default": 50
                        }
                    }
                }
            )
        ]

    async def handle_tool_call(self, name: str, arguments: Dict[str, Any]) -> Any:
        """Handle Audit Manager tool calls."""
        try:
            if name == "auditmanager_list_assessments":
                return await self._list_assessments(arguments)
            elif name == "auditmanager_list_frameworks":
                return await self._list_frameworks(arguments)
            else:
                raise ValueError(f"Unknown Audit Manager tool: {name}")

        except ClientError as e:
            logger.error(f"AWS client error in {name}: {e}")
            return {"error": str(e), "service": "auditmanager", "operation": name}
        except Exception as e:
            logger.error(f"Unexpected error in {name}: {e}")
            return {"error": str(e), "service": "auditmanager", "operation": name}

    async def _list_assessments(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """List assessments."""
        params = {}
        if "status" in arguments:
            params["status"] = arguments["status"]
        if "max_results" in arguments:
            params["maxResults"] = arguments["max_results"]

        response = self.client.list_assessments(**params)
        
        return {
            "assessment_metadata": response.get("assessmentMetadata", []),
            "next_token": response.get("nextToken")
        }

    async def _list_frameworks(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """List frameworks."""
        params = {}
        if "framework_type" in arguments:
            params["frameworkType"] = arguments["framework_type"]
        if "max_results" in arguments:
            params["maxResults"] = arguments["max_results"]

        response = self.client.list_assessment_frameworks(**params)
        
        return {
            "framework_metadata_list": response.get("frameworkMetadataList", []),
            "next_token": response.get("nextToken")
        }