"""Shield service implementation for AWS Security MCP Server."""

import logging
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError
import mcp.types as types

logger = logging.getLogger(__name__)


class ShieldService:
    """Service for handling Shield operations."""

    def __init__(self, session: boto3.Session):
        """Initialize the Shield service."""
        self.client = session.client("shield")

    def get_tools(self) -> List[types.Tool]:
        """Get available Shield tools."""
        return [
            types.Tool(
                name="shield_list_protections",
                description="List Shield protections",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "max_results": {
                            "type": "integer",
                            "minimum": 0,
                            "maximum": 100,
                            "default": 50
                        }
                    }
                }
            ),
            types.Tool(
                name="shield_describe_protection",
                description="Describe a specific Shield protection",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "protection_id": {
                            "type": "string",
                            "description": "ID of the protection"
                        },
                        "resource_arn": {
                            "type": "string",
                            "description": "ARN of the protected resource"
                        }
                    }
                }
            ),
            types.Tool(
                name="shield_get_subscription_state",
                description="Get Shield Advanced subscription state",
                inputSchema={
                    "type": "object",
                    "properties": {}
                }
            ),
            types.Tool(
                name="shield_list_attacks",
                description="List DDoS attacks",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "resource_arns": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of resource ARNs to filter by"
                        },
                        "start_time": {
                            "type": "string",
                            "description": "Start time for attack lookup (ISO format)"
                        },
                        "end_time": {
                            "type": "string",
                            "description": "End time for attack lookup (ISO format)"
                        },
                        "max_results": {
                            "type": "integer",
                            "minimum": 0,
                            "maximum": 100,
                            "default": 50
                        }
                    }
                }
            )
        ]

    async def handle_tool_call(self, name: str, arguments: Dict[str, Any]) -> Any:
        """Handle Shield tool calls."""
        try:
            if name == "shield_list_protections":
                return await self._list_protections(arguments)
            elif name == "shield_describe_protection":
                return await self._describe_protection(arguments)
            elif name == "shield_get_subscription_state":
                return await self._get_subscription_state(arguments)
            elif name == "shield_list_attacks":
                return await self._list_attacks(arguments)
            else:
                raise ValueError(f"Unknown Shield tool: {name}")

        except ClientError as e:
            logger.error(f"AWS client error in {name}: {e}")
            return {"error": str(e), "service": "shield", "operation": name}
        except Exception as e:
            logger.error(f"Unexpected error in {name}: {e}")
            return {"error": str(e), "service": "shield", "operation": name}

    async def _list_protections(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """List Shield protections."""
        params = {}
        if "max_results" in arguments:
            params["MaxResults"] = arguments["max_results"]

        response = self.client.list_protections(**params)
        
        protections = []
        for protection in response.get("Protections", []):
            protections.append({
                "id": protection.get("Id"),
                "name": protection.get("Name"),
                "resource_arn": protection.get("ResourceArn"),
                "health_check_ids": protection.get("HealthCheckIds", []),
                "protection_arn": protection.get("ProtectionArn"),
                "application_layer_automatic_response_configuration": protection.get("ApplicationLayerAutomaticResponseConfiguration")
            })

        return {
            "protections": protections,
            "total_count": len(protections),
            "next_token": response.get("NextToken")
        }

    async def _describe_protection(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Describe a Shield protection."""
        params = {}
        if "protection_id" in arguments:
            params["ProtectionId"] = arguments["protection_id"]
        elif "resource_arn" in arguments:
            params["ResourceArn"] = arguments["resource_arn"]
        else:
            raise ValueError("Either protection_id or resource_arn must be provided")

        response = self.client.describe_protection(**params)
        
        protection = response.get("Protection", {})
        return {
            "id": protection.get("Id"),
            "name": protection.get("Name"),
            "resource_arn": protection.get("ResourceArn"),
            "health_check_ids": protection.get("HealthCheckIds", []),
            "protection_arn": protection.get("ProtectionArn"),
            "application_layer_automatic_response_configuration": protection.get("ApplicationLayerAutomaticResponseConfiguration")
        }

    async def _get_subscription_state(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get Shield Advanced subscription state."""
        response = self.client.get_subscription_state()
        
        return {
            "subscription_state": response.get("SubscriptionState")
        }

    async def _list_attacks(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """List DDoS attacks."""
        from datetime import datetime
        
        params = {}
        if "resource_arns" in arguments:
            params["ResourceArns"] = arguments["resource_arns"]
        if "start_time" in arguments:
            params["StartTime"] = {
                "FromInclusive": datetime.fromisoformat(arguments["start_time"].replace('Z', '+00:00'))
            }
        if "end_time" in arguments:
            if "StartTime" not in params:
                params["StartTime"] = {}
            params["EndTime"] = {
                "ToExclusive": datetime.fromisoformat(arguments["end_time"].replace('Z', '+00:00'))
            }
        if "max_results" in arguments:
            params["MaxResults"] = arguments["max_results"]

        response = self.client.list_attacks(**params)
        
        attacks = []
        for attack in response.get("AttackSummaries", []):
            attacks.append({
                "attack_id": attack.get("AttackId"),
                "resource_arn": attack.get("ResourceArn"),
                "start_time": attack.get("StartTime").isoformat() if attack.get("StartTime") else None,
                "end_time": attack.get("EndTime").isoformat() if attack.get("EndTime") else None,
                "attack_vectors": attack.get("AttackVectors", [])
            })

        return {
            "attacks": attacks,
            "total_count": len(attacks),
            "next_token": response.get("NextToken")
        }