"""Secrets Manager service implementation for AWS Security MCP Server."""

import logging
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError
import mcp.types as types

logger = logging.getLogger(__name__)


class SecretsManagerService:
    """Service for handling Secrets Manager operations."""

    def __init__(self, session: boto3.Session):
        """Initialize the Secrets Manager service."""
        self.client = session.client("secretsmanager")

    def get_tools(self) -> List[types.Tool]:
        """Get available Secrets Manager tools."""
        return [
            types.Tool(
                name="secretsmanager_list_secrets",
                description="List secrets in Secrets Manager",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "include_planned_deletion": {
                            "type": "boolean",
                            "description": "Include secrets scheduled for deletion",
                            "default": False
                        },
                        "max_results": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 100,
                            "default": 50
                        },
                        "sort_order": {
                            "type": "string",
                            "enum": ["asc", "desc"],
                            "description": "Sort order for results"
                        }
                    }
                }
            ),
            types.Tool(
                name="secretsmanager_describe_secret",
                description="Get details for a specific secret",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "secret_id": {
                            "type": "string",
                            "description": "Name or ARN of the secret"
                        }
                    },
                    "required": ["secret_id"]
                }
            ),
            types.Tool(
                name="secretsmanager_get_resource_policy",
                description="Get resource policy for a secret",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "secret_id": {
                            "type": "string",
                            "description": "Name or ARN of the secret"
                        }
                    },
                    "required": ["secret_id"]
                }
            )
        ]

    async def handle_tool_call(self, name: str, arguments: Dict[str, Any]) -> Any:
        """Handle Secrets Manager tool calls."""
        try:
            if name == "secretsmanager_list_secrets":
                return await self._list_secrets(arguments)
            elif name == "secretsmanager_describe_secret":
                return await self._describe_secret(arguments)
            elif name == "secretsmanager_get_resource_policy":
                return await self._get_resource_policy(arguments)
            else:
                raise ValueError(f"Unknown Secrets Manager tool: {name}")

        except ClientError as e:
            logger.error(f"AWS client error in {name}: {e}")
            return {"error": str(e), "service": "secretsmanager", "operation": name}
        except Exception as e:
            logger.error(f"Unexpected error in {name}: {e}")
            return {"error": str(e), "service": "secretsmanager", "operation": name}

    async def _list_secrets(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """List secrets in Secrets Manager."""
        params = {}
        if "include_planned_deletion" in arguments:
            params["IncludePlannedDeletion"] = arguments["include_planned_deletion"]
        if "max_results" in arguments:
            params["MaxResults"] = arguments["max_results"]
        if "sort_order" in arguments:
            params["SortOrder"] = arguments["sort_order"]

        response = self.client.list_secrets(**params)
        
        secrets = []
        for secret in response.get("SecretList", []):
            secrets.append({
                "arn": secret.get("ARN"),
                "name": secret.get("Name"),
                "description": secret.get("Description"),
                "kms_key_id": secret.get("KmsKeyId"),
                "rotation_enabled": secret.get("RotationEnabled"),
                "rotation_lambda_arn": secret.get("RotationLambdaARN"),
                "rotation_rules": secret.get("RotationRules"),
                "last_rotated_date": secret.get("LastRotatedDate").isoformat() if secret.get("LastRotatedDate") else None,
                "last_changed_date": secret.get("LastChangedDate").isoformat() if secret.get("LastChangedDate") else None,
                "last_accessed_date": secret.get("LastAccessedDate").isoformat() if secret.get("LastAccessedDate") else None,
                "deleted_date": secret.get("DeletedDate").isoformat() if secret.get("DeletedDate") else None,
                "next_rotation_date": secret.get("NextRotationDate").isoformat() if secret.get("NextRotationDate") else None,
                "tags": secret.get("Tags", []),
                "secret_versions_to_stages": secret.get("SecretVersionsToStages", {}),
                "owning_service": secret.get("OwningService"),
                "created_date": secret.get("CreatedDate").isoformat() if secret.get("CreatedDate") else None,
                "primary_region": secret.get("PrimaryRegion"),
                "replication_status": secret.get("ReplicationStatus", [])
            })

        return {
            "secrets": secrets,
            "total_count": len(secrets),
            "next_token": response.get("NextToken")
        }

    async def _describe_secret(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Describe a specific secret."""
        secret_id = arguments["secret_id"]
        response = self.client.describe_secret(SecretId=secret_id)
        
        return {
            "arn": response.get("ARN"),
            "name": response.get("Name"),
            "description": response.get("Description"),
            "kms_key_id": response.get("KmsKeyId"),
            "rotation_enabled": response.get("RotationEnabled"),
            "rotation_lambda_arn": response.get("RotationLambdaARN"),
            "rotation_rules": response.get("RotationRules"),
            "last_rotated_date": response.get("LastRotatedDate").isoformat() if response.get("LastRotatedDate") else None,
            "last_changed_date": response.get("LastChangedDate").isoformat() if response.get("LastChangedDate") else None,
            "last_accessed_date": response.get("LastAccessedDate").isoformat() if response.get("LastAccessedDate") else None,
            "deleted_date": response.get("DeletedDate").isoformat() if response.get("DeletedDate") else None,
            "next_rotation_date": response.get("NextRotationDate").isoformat() if response.get("NextRotationDate") else None,
            "tags": response.get("Tags", []),
            "version_ids_to_stages": response.get("VersionIdsToStages", {}),
            "owning_service": response.get("OwningService"),
            "created_date": response.get("CreatedDate").isoformat() if response.get("CreatedDate") else None,
            "primary_region": response.get("PrimaryRegion"),
            "replication_status": response.get("ReplicationStatus", [])
        }

    async def _get_resource_policy(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get resource policy for a secret."""
        secret_id = arguments["secret_id"]
        
        try:
            response = self.client.get_resource_policy(SecretId=secret_id)
            return {
                "arn": response.get("ARN"),
                "name": response.get("Name"),
                "resource_policy": response.get("ResourcePolicy")
            }
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return {"error": "No resource policy found for this secret"}
            raise