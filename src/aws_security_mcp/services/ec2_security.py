"""EC2 Security service implementation for AWS Security MCP Server."""

import logging
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError
import mcp.types as types

logger = logging.getLogger(__name__)


class EC2SecurityService:
    """Service for handling EC2 security operations."""

    def __init__(self, session: boto3.Session):
        """Initialize the EC2 Security service."""
        self.ec2_client = session.client("ec2")
        self.s3_client = session.client("s3")

    def get_tools(self) -> List[types.Tool]:
        """Get available EC2 Security tools."""
        return [
            types.Tool(
                name="ec2_describe_security_groups",
                description="List EC2 security groups",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "group_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of security group IDs"
                        },
                        "group_names": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of security group names"
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
                name="ec2_describe_network_acls",
                description="List EC2 network ACLs",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "network_acl_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of network ACL IDs"
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
                name="s3_list_buckets",
                description="List S3 buckets",
                inputSchema={
                    "type": "object",
                    "properties": {}
                }
            ),
            types.Tool(
                name="s3_get_bucket_policy",
                description="Get S3 bucket policy",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "bucket": {
                            "type": "string",
                            "description": "Name of the S3 bucket"
                        }
                    },
                    "required": ["bucket"]
                }
            )
        ]

    async def handle_tool_call(self, name: str, arguments: Dict[str, Any]) -> Any:
        """Handle EC2 Security tool calls."""
        try:
            if name == "ec2_describe_security_groups":
                return await self._describe_security_groups(arguments)
            elif name == "ec2_describe_network_acls":
                return await self._describe_network_acls(arguments)
            elif name == "s3_list_buckets":
                return await self._list_buckets(arguments)
            elif name == "s3_get_bucket_policy":
                return await self._get_bucket_policy(arguments)
            else:
                raise ValueError(f"Unknown EC2 Security tool: {name}")

        except ClientError as e:
            logger.error(f"AWS client error in {name}: {e}")
            return {"error": str(e), "service": "ec2_security", "operation": name}
        except Exception as e:
            logger.error(f"Unexpected error in {name}: {e}")
            return {"error": str(e), "service": "ec2_security", "operation": name}

    async def _describe_security_groups(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Describe security groups."""
        params = {}
        if "group_ids" in arguments:
            params["GroupIds"] = arguments["group_ids"]
        if "group_names" in arguments:
            params["GroupNames"] = arguments["group_names"]
        if "max_results" in arguments:
            params["MaxResults"] = arguments["max_results"]

        response = self.ec2_client.describe_security_groups(**params)
        
        return {
            "security_groups": response.get("SecurityGroups", []),
            "next_token": response.get("NextToken")
        }

    async def _describe_network_acls(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Describe network ACLs."""
        params = {}
        if "network_acl_ids" in arguments:
            params["NetworkAclIds"] = arguments["network_acl_ids"]
        if "max_results" in arguments:
            params["MaxResults"] = arguments["max_results"]

        response = self.ec2_client.describe_network_acls(**params)
        
        return {
            "network_acls": response.get("NetworkAcls", []),
            "next_token": response.get("NextToken")
        }

    async def _list_buckets(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """List S3 buckets."""
        response = self.s3_client.list_buckets()
        
        return {
            "buckets": response.get("Buckets", []),
            "owner": response.get("Owner", {})
        }

    async def _get_bucket_policy(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get S3 bucket policy."""
        bucket = arguments["bucket"]
        
        try:
            response = self.s3_client.get_bucket_policy(Bucket=bucket)
            return {
                "bucket": bucket,
                "policy": response.get("Policy")
            }
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
                return {"bucket": bucket, "policy": None, "message": "No bucket policy exists"}
            raise