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
            ),
            types.Tool(
                name="s3_get_bucket_encryption",
                description="Get S3 bucket encryption configuration",
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
            ),
            types.Tool(
                name="s3_get_bucket_public_access_block",
                description="Get S3 bucket public access block configuration",
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
            ),
            types.Tool(
                name="ec2_describe_instances",
                description="List EC2 instances with security details",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "instance_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of instance IDs"
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
                name="ec2_audit_key_pairs",
                description="Audit EC2 key pairs and their usage",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "check_unused_keys": {
                            "type": "boolean",
                            "default": True,
                            "description": "Check for unused key pairs"
                        }
                    }
                }
            ),
            types.Tool(
                name="ec2_audit_security_groups",
                description="Audit security groups for risky configurations",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "check_open_ports": {
                            "type": "boolean",
                            "default": True,
                            "description": "Check for open ports (0.0.0.0/0)"
                        }
                    }
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
            elif name == "s3_get_bucket_encryption":
                return await self._get_bucket_encryption(arguments)
            elif name == "s3_get_bucket_public_access_block":
                return await self._get_bucket_public_access_block(arguments)
            elif name == "ec2_describe_instances":
                return await self._describe_instances(arguments)
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

    async def _get_bucket_encryption(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get S3 bucket encryption."""
        bucket = arguments["bucket"]
        
        try:
            response = self.s3_client.get_bucket_encryption(Bucket=bucket)
            return {
                "bucket": bucket,
                "server_side_encryption_configuration": response.get("ServerSideEncryptionConfiguration")
            }
        except ClientError as e:
            if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                return {"bucket": bucket, "encryption": None, "message": "No encryption configuration"}
            raise

    async def _get_bucket_public_access_block(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get S3 bucket public access block."""
        bucket = arguments["bucket"]
        
        try:
            response = self.s3_client.get_public_access_block(Bucket=bucket)
            return {
                "bucket": bucket,
                "public_access_block_configuration": response.get("PublicAccessBlockConfiguration")
            }
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                return {"bucket": bucket, "public_access_block": None, "message": "No public access block configuration"}
            raise

    async def _describe_instances(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Describe EC2 instances."""
        params = {}
        if "instance_ids" in arguments:
            params["InstanceIds"] = arguments["instance_ids"]
        if "max_results" in arguments:
            params["MaxResults"] = arguments["max_results"]

        response = self.ec2_client.describe_instances(**params)
        
        instances = []
        for reservation in response.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                instances.append({
                    "instance_id": instance.get("InstanceId"),
                    "instance_type": instance.get("InstanceType"),
                    "state": instance.get("State", {}).get("Name"),
                    "vpc_id": instance.get("VpcId"),
                    "subnet_id": instance.get("SubnetId"),
                    "security_groups": instance.get("SecurityGroups", []),
                    "public_ip_address": instance.get("PublicIpAddress"),
                    "private_ip_address": instance.get("PrivateIpAddress"),
                    "key_name": instance.get("KeyName"),
                    "launch_time": instance.get("LaunchTime").isoformat() if instance.get("LaunchTime") else None,
                    "tags": instance.get("Tags", [])
                })
        
        return {
            "instances": instances,
            "total_count": len(instances),
            "next_token": response.get("NextToken")
        }