"""KMS service implementation for AWS Security MCP Server."""

import logging
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError
import mcp.types as types

logger = logging.getLogger(__name__)


class KMSService:
    """Service for handling KMS operations."""

    def __init__(self, session: boto3.Session):
        """Initialize the KMS service."""
        self.client = session.client("kms")

    def get_tools(self) -> List[types.Tool]:
        """Get available KMS tools."""
        return [
            types.Tool(
                name="kms_list_keys",
                description="List KMS keys",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "limit": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 1000,
                            "default": 100
                        }
                    }
                }
            ),
            types.Tool(
                name="kms_describe_key",
                description="Get details for a specific KMS key",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "key_id": {
                            "type": "string",
                            "description": "The key ID or ARN"
                        }
                    },
                    "required": ["key_id"]
                }
            ),
            types.Tool(
                name="kms_get_key_rotation_status",
                description="Get key rotation status",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "key_id": {
                            "type": "string",
                            "description": "The key ID or ARN"
                        }
                    },
                    "required": ["key_id"]
                }
            )
        ]

    async def handle_tool_call(self, name: str, arguments: Dict[str, Any]) -> Any:
        """Handle KMS tool calls."""
        try:
            if name == "kms_list_keys":
                return await self._list_keys(arguments)
            elif name == "kms_describe_key":
                return await self._describe_key(arguments)
            elif name == "kms_get_key_rotation_status":
                return await self._get_key_rotation_status(arguments)
            else:
                raise ValueError(f"Unknown KMS tool: {name}")

        except ClientError as e:
            logger.error(f"AWS client error in {name}: {e}")
            return {"error": str(e), "service": "kms", "operation": name}
        except Exception as e:
            logger.error(f"Unexpected error in {name}: {e}")
            return {"error": str(e), "service": "kms", "operation": name}

    async def _list_keys(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """List KMS keys."""
        params = {}
        if "limit" in arguments:
            params["Limit"] = arguments["limit"]

        response = self.client.list_keys(**params)
        
        keys = []
        for key in response.get("Keys", []):
            keys.append({
                "key_id": key["KeyId"],
                "key_arn": key["KeyArn"]
            })

        return {
            "keys": keys,
            "total_count": len(keys),
            "truncated": response.get("Truncated", False)
        }

    async def _describe_key(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Describe a KMS key."""
        key_id = arguments["key_id"]
        response = self.client.describe_key(KeyId=key_id)
        
        key_metadata = response["KeyMetadata"]
        return {
            "key_id": key_metadata["KeyId"],
            "arn": key_metadata["Arn"],
            "creation_date": key_metadata["CreationDate"].isoformat(),
            "enabled": key_metadata["Enabled"],
            "description": key_metadata.get("Description"),
            "key_usage": key_metadata["KeyUsage"],
            "key_state": key_metadata["KeyState"],
            "origin": key_metadata["Origin"],
            "key_manager": key_metadata["KeyManager"]
        }

    async def _get_key_rotation_status(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get key rotation status."""
        key_id = arguments["key_id"]
        response = self.client.get_key_rotation_status(KeyId=key_id)
        
        return {
            "key_id": key_id,
            "key_rotation_enabled": response["KeyRotationEnabled"]
        }