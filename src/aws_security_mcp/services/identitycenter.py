"""Identity Center service implementation for AWS Security MCP Server."""

import logging
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError
import mcp.types as types

logger = logging.getLogger(__name__)


class IdentityCenterService:
    """Service for handling Identity Center operations."""

    def __init__(self, session: boto3.Session):
        """Initialize the Identity Center service."""
        self.client = session.client("sso-admin")

    def get_tools(self) -> List[types.Tool]:
        """Get available Identity Center tools."""
        return [
            types.Tool(
                name="identitycenter_list_instances",
                description="List Identity Center instances",
                inputSchema={
                    "type": "object",
                    "properties": {
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
                name="identitycenter_list_permission_sets",
                description="List Identity Center permission sets",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "instance_arn": {
                            "type": "string",
                            "description": "ARN of the Identity Center instance"
                        },
                        "max_results": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 100,
                            "default": 50
                        }
                    },
                    "required": ["instance_arn"]
                }
            )
        ]

    async def handle_tool_call(self, name: str, arguments: Dict[str, Any]) -> Any:
        """Handle Identity Center tool calls."""
        try:
            if name == "identitycenter_list_instances":
                return await self._list_instances(arguments)
            elif name == "identitycenter_list_permission_sets":
                return await self._list_permission_sets(arguments)
            else:
                raise ValueError(f"Unknown Identity Center tool: {name}")

        except ClientError as e:
            logger.error(f"AWS client error in {name}: {e}")
            return {"error": str(e), "service": "identitycenter", "operation": name}
        except Exception as e:
            logger.error(f"Unexpected error in {name}: {e}")
            return {"error": str(e), "service": "identitycenter", "operation": name}

    async def _list_instances(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """List Identity Center instances."""
        params = {}
        if "max_results" in arguments:
            params["MaxResults"] = arguments["max_results"]

        response = self.client.list_instances(**params)
        
        return {
            "instances": response.get("Instances", []),
            "next_token": response.get("NextToken")
        }

    async def _list_permission_sets(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """List permission sets."""
        params = {
            "InstanceArn": arguments["instance_arn"]
        }
        if "max_results" in arguments:
            params["MaxResults"] = arguments["max_results"]

        response = self.client.list_permission_sets(**params)
        
        return {
            "permission_sets": response.get("PermissionSets", []),
            "next_token": response.get("NextToken")
        }