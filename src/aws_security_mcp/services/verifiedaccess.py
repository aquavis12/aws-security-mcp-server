"""Verified Access service implementation for AWS Security MCP Server."""

import logging
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError
import mcp.types as types

logger = logging.getLogger(__name__)


class VerifiedAccessService:
    """Service for handling Verified Access operations."""

    def __init__(self, session: boto3.Session):
        """Initialize the Verified Access service."""
        self.client = session.client("ec2")

    def get_tools(self) -> List[types.Tool]:
        """Get available Verified Access tools."""
        return [
            types.Tool(
                name="verifiedaccess_describe_instances",
                description="List Verified Access instances",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "verified_access_instance_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of Verified Access instance IDs"
                        },
                        "max_results": {
                            "type": "integer",
                            "minimum": 5,
                            "maximum": 1000,
                            "default": 100
                        }
                    }
                }
            ),
            types.Tool(
                name="verifiedaccess_describe_groups",
                description="List Verified Access groups",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "verified_access_group_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of Verified Access group IDs"
                        },
                        "max_results": {
                            "type": "integer",
                            "minimum": 5,
                            "maximum": 1000,
                            "default": 100
                        }
                    }
                }
            )
        ]

    async def handle_tool_call(self, name: str, arguments: Dict[str, Any]) -> Any:
        """Handle Verified Access tool calls."""
        try:
            if name == "verifiedaccess_describe_instances":
                return await self._describe_instances(arguments)
            elif name == "verifiedaccess_describe_groups":
                return await self._describe_groups(arguments)
            else:
                raise ValueError(f"Unknown Verified Access tool: {name}")

        except ClientError as e:
            logger.error(f"AWS client error in {name}: {e}")
            return {"error": str(e), "service": "verifiedaccess", "operation": name}
        except Exception as e:
            logger.error(f"Unexpected error in {name}: {e}")
            return {"error": str(e), "service": "verifiedaccess", "operation": name}

    async def _describe_instances(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Describe Verified Access instances."""
        params = {}
        if "verified_access_instance_ids" in arguments:
            params["VerifiedAccessInstanceIds"] = arguments["verified_access_instance_ids"]
        if "max_results" in arguments:
            params["MaxResults"] = arguments["max_results"]

        response = self.client.describe_verified_access_instances(**params)
        
        return {
            "verified_access_instances": response.get("VerifiedAccessInstances", []),
            "next_token": response.get("NextToken")
        }

    async def _describe_groups(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Describe Verified Access groups."""
        params = {}
        if "verified_access_group_ids" in arguments:
            params["VerifiedAccessGroupIds"] = arguments["verified_access_group_ids"]
        if "max_results" in arguments:
            params["MaxResults"] = arguments["max_results"]

        response = self.client.describe_verified_access_groups(**params)
        
        return {
            "verified_access_groups": response.get("VerifiedAccessGroups", []),
            "next_token": response.get("NextToken")
        }