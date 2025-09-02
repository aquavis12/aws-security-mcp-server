"""VPC Lattice service implementation for AWS Security MCP Server."""

import logging
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError
import mcp.types as types

logger = logging.getLogger(__name__)


class VPCLatticeService:
    """Service for handling VPC Lattice operations."""

    def __init__(self, session: boto3.Session):
        """Initialize the VPC Lattice service."""
        self.client = session.client("vpc-lattice")

    def get_tools(self) -> List[types.Tool]:
        """Get available VPC Lattice tools."""
        return [
            types.Tool(
                name="vpclattice_list_services",
                description="List VPC Lattice services",
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
                name="vpclattice_list_service_networks",
                description="List VPC Lattice service networks",
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
                name="vpclattice_get_auth_policy",
                description="Get VPC Lattice auth policy",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "resource_identifier": {
                            "type": "string",
                            "description": "Resource identifier (service or service network)"
                        }
                    },
                    "required": ["resource_identifier"]
                }
            )
        ]

    async def handle_tool_call(self, name: str, arguments: Dict[str, Any]) -> Any:
        """Handle VPC Lattice tool calls."""
        try:
            if name == "vpclattice_list_services":
                return await self._list_services(arguments)
            elif name == "vpclattice_list_service_networks":
                return await self._list_service_networks(arguments)
            elif name == "vpclattice_get_auth_policy":
                return await self._get_auth_policy(arguments)
            else:
                raise ValueError(f"Unknown VPC Lattice tool: {name}")

        except ClientError as e:
            logger.error(f"AWS client error in {name}: {e}")
            return {"error": str(e), "service": "vpclattice", "operation": name}
        except Exception as e:
            logger.error(f"Unexpected error in {name}: {e}")
            return {"error": str(e), "service": "vpclattice", "operation": name}

    async def _list_services(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """List VPC Lattice services."""
        params = {}
        if "max_results" in arguments:
            params["maxResults"] = arguments["max_results"]

        response = self.client.list_services(**params)
        
        return {
            "items": response.get("items", []),
            "next_token": response.get("nextToken")
        }

    async def _list_service_networks(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """List VPC Lattice service networks."""
        params = {}
        if "max_results" in arguments:
            params["maxResults"] = arguments["max_results"]

        response = self.client.list_service_networks(**params)
        
        return {
            "items": response.get("items", []),
            "next_token": response.get("nextToken")
        }

    async def _get_auth_policy(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get VPC Lattice auth policy."""
        resource_identifier = arguments["resource_identifier"]
        
        try:
            response = self.client.get_auth_policy(resourceIdentifier=resource_identifier)
            return {
                "resource_identifier": resource_identifier,
                "policy": response.get("policy"),
                "state": response.get("state"),
                "created_at": response.get("createdAt").isoformat() if response.get("createdAt") else None,
                "last_updated_at": response.get("lastUpdatedAt").isoformat() if response.get("lastUpdatedAt") else None
            }
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return {"resource_identifier": resource_identifier, "policy": None, "message": "No auth policy found"}
            raise