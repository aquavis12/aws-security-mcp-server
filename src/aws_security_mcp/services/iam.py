"""IAM service implementation for AWS Security MCP Server."""

import json
import logging
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError
import mcp.types as types

logger = logging.getLogger(__name__)


class IAMService:
    """Service for handling IAM operations."""

    def __init__(self, session: boto3.Session):
        """Initialize the IAM service."""
        self.client = session.client("iam")

    def get_tools(self) -> List[types.Tool]:
        """Get available IAM tools."""
        return [
            types.Tool(
                name="iam_list_users",
                description="List IAM users in the account",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path_prefix": {
                            "type": "string",
                            "description": "The path prefix for filtering users"
                        },
                        "max_items": {
                            "type": "integer",
                            "description": "Maximum number of users to return",
                            "minimum": 1,
                            "maximum": 1000,
                            "default": 50
                        }
                    }
                }
            ),
            types.Tool(
                name="iam_list_roles",
                description="List IAM roles in the account",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path_prefix": {
                            "type": "string",
                            "description": "The path prefix for filtering roles"
                        },
                        "max_items": {
                            "type": "integer",
                            "description": "Maximum number of roles to return",
                            "minimum": 1,
                            "maximum": 1000,
                            "default": 50
                        }
                    }
                }
            ),
            types.Tool(
                name="iam_list_policies",
                description="List IAM policies in the account",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "scope": {
                            "type": "string",
                            "enum": ["All", "AWS", "Local"],
                            "description": "Filter policies by scope",
                            "default": "Local"
                        },
                        "only_attached": {
                            "type": "boolean",
                            "description": "Filter to only attached policies",
                            "default": False
                        },
                        "max_items": {
                            "type": "integer",
                            "description": "Maximum number of policies to return",
                            "minimum": 1,
                            "maximum": 1000,
                            "default": 50
                        }
                    }
                }
            ),
            types.Tool(
                name="iam_get_user",
                description="Get details for a specific IAM user",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "user_name": {
                            "type": "string",
                            "description": "Name of the user to retrieve"
                        }
                    },
                    "required": ["user_name"]
                }
            ),
            types.Tool(
                name="iam_get_account_summary",
                description="Get IAM account summary with usage statistics",
                inputSchema={
                    "type": "object",
                    "properties": {}
                }
            )
        ]

    async def handle_tool_call(self, name: str, arguments: Dict[str, Any]) -> Any:
        """Handle IAM tool calls."""
        try:
            if name == "iam_list_users":
                return await self._list_users(arguments)
            elif name == "iam_list_roles":
                return await self._list_roles(arguments)
            elif name == "iam_list_policies":
                return await self._list_policies(arguments)
            elif name == "iam_get_user":
                return await self._get_user(arguments)
            elif name == "iam_get_account_summary":
                return await self._get_account_summary(arguments)
            else:
                raise ValueError(f"Unknown IAM tool: {name}")
                
        except ClientError as e:
            logger.error(f"AWS client error in {name}: {e}")
            return {"error": str(e), "service": "iam", "operation": name}
        except Exception as e:
            logger.error(f"Unexpected error in {name}: {e}")
            return {"error": str(e), "service": "iam", "operation": name}

    async def _list_users(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """List IAM users."""
        params = {}
        
        if "path_prefix" in arguments:
            params["PathPrefix"] = arguments["path_prefix"]
        if "max_items" in arguments:
            params["MaxItems"] = arguments["max_items"]
            
        response = self.client.list_users(**params)
        
        users = []
        for user in response.get("Users", []):
            users.append({
                "user_name": user["UserName"],
                "user_id": user["UserId"],
                "arn": user["Arn"],
                "path": user["Path"],
                "create_date": user["CreateDate"].isoformat(),
                "password_last_used": user.get("PasswordLastUsed").isoformat() if user.get("PasswordLastUsed") else None,
                "tags": user.get("Tags", [])
            })
            
        return {
            "users": users,
            "total_count": len(users),
            "is_truncated": response.get("IsTruncated", False)
        }

    async def _list_roles(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """List IAM roles."""
        params = {}
        
        if "path_prefix" in arguments:
            params["PathPrefix"] = arguments["path_prefix"]
        if "max_items" in arguments:
            params["MaxItems"] = arguments["max_items"]
            
        response = self.client.list_roles(**params)
        
        roles = []
        for role in response.get("Roles", []):
            roles.append({
                "role_name": role["RoleName"],
                "role_id": role["RoleId"],
                "arn": role["Arn"],
                "path": role["Path"],
                "create_date": role["CreateDate"].isoformat(),
                "description": role.get("Description"),
                "max_session_duration": role.get("MaxSessionDuration"),
                "tags": role.get("Tags", [])
            })
            
        return {
            "roles": roles,
            "total_count": len(roles),
            "is_truncated": response.get("IsTruncated", False)
        }

    async def _list_policies(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """List IAM policies."""
        params = {
            "Scope": arguments.get("scope", "Local"),
            "OnlyAttached": arguments.get("only_attached", False)
        }
        
        if "max_items" in arguments:
            params["MaxItems"] = arguments["max_items"]
            
        response = self.client.list_policies(**params)
        
        policies = []
        for policy in response.get("Policies", []):
            policies.append({
                "policy_name": policy["PolicyName"],
                "policy_id": policy["PolicyId"],
                "arn": policy["Arn"],
                "path": policy["Path"],
                "default_version_id": policy["DefaultVersionId"],
                "attachment_count": policy["AttachmentCount"],
                "is_attachable": policy["IsAttachable"],
                "description": policy.get("Description"),
                "create_date": policy["CreateDate"].isoformat(),
                "update_date": policy["UpdateDate"].isoformat()
            })
            
        return {
            "policies": policies,
            "total_count": len(policies),
            "is_truncated": response.get("IsTruncated", False)
        }

    async def _get_user(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get details for a specific user."""
        user_name = arguments["user_name"]
        response = self.client.get_user(UserName=user_name)
        
        user = response["User"]
        return {
            "user_name": user["UserName"],
            "user_id": user["UserId"],
            "arn": user["Arn"],
            "path": user["Path"],
            "create_date": user["CreateDate"].isoformat(),
            "password_last_used": user.get("PasswordLastUsed").isoformat() if user.get("PasswordLastUsed") else None,
            "tags": user.get("Tags", [])
        }

    async def _get_account_summary(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get IAM account summary with usage statistics."""
        response = self.client.get_account_summary()
        
        summary_map = response.get("SummaryMap", {})
        
        return {
            "users": summary_map.get("Users", 0),
            "users_quota": summary_map.get("UsersQuota", 0),
            "groups": summary_map.get("Groups", 0),
            "groups_quota": summary_map.get("GroupsQuota", 0),
            "roles": summary_map.get("Roles", 0),
            "roles_quota": summary_map.get("RolesQuota", 0),
            "policies": summary_map.get("Policies", 0),
            "policies_quota": summary_map.get("PoliciesQuota", 0),
            "account_mfa_enabled": summary_map.get("AccountMFAEnabled", 0),
            "global_endpoint_token_version": summary_map.get("GlobalEndpointTokenVersion", 0)
        }

import json
import logging
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError
import mcp.types as types

from ..models import IAMUser, IAMRole, IAMPolicy, IAMListUsersParameters, IAMListRolesParameters

logger = logging.getLogger(__name__)


class IAMService:
    """Service for handling IAM operations."""

    def __init__(self, session: boto3.Session):
        """Initialize the IAM service."""
        self.client = session.client("iam")

    def get_tools(self) -> List[types.Tool]:
        """Get available IAM tools."""
        return [
            types.Tool(
                name="iam_list_users",
                description="List IAM users in the account",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path_prefix": {
                            "type": "string",
                            "description": "The path prefix for filtering users"
                        },
                        "marker": {
                            "type": "string", 
                            "description": "Pagination marker for listing users"
                        },
                        "max_items": {
                            "type": "integer",
                            "description": "Maximum number of users to return",
                            "minimum": 1,
                            "maximum": 1000,
                            "default": 50
                        }
                    }
                }
            ),
            types.Tool(
                name="iam_list_roles",
                description="List IAM roles in the account",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path_prefix": {
                            "type": "string",
                            "description": "The path prefix for filtering roles"
                        },
                        "marker": {
                            "type": "string",
                            "description": "Pagination marker for listing roles"
                        },
                        "max_items": {
                            "type": "integer",
                            "description": "Maximum number of roles to return",
                            "minimum": 1,
                            "maximum": 1000,
                            "default": 50
                        }
                    }
                }
            ),
            types.Tool(
                name="iam_list_policies",
                description="List IAM policies in the account",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "scope": {
                            "type": "string",
                            "enum": ["All", "AWS", "Local"],
                            "description": "Filter policies by scope",
                            "default": "Local"
                        },
                        "only_attached": {
                            "type": "boolean",
                            "description": "Filter to only attached policies",
                            "default": False
                        },
                        "path_prefix": {
                            "type": "string",
                            "description": "The path prefix for filtering policies"
                        },
                        "policy_usage_filter": {
                            "type": "string",
                            "enum": ["PermissionsPolicy", "PermissionsBoundary"],
                            "description": "Filter policies by usage type"
                        },
                        "max_items": {
                            "type": "integer",
                            "description": "Maximum number of policies to return",
                            "minimum": 1,
                            "maximum": 1000,
                            "default": 50
                        }
                    }
                }
            ),
            types.Tool(
                name="iam_get_user",
                description="Get details for a specific IAM user",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "user_name": {
                            "type": "string",
                            "description": "Name of the user to retrieve"
                        }
                    },
                    "required": ["user_name"]
                }
            ),
            types.Tool(
                name="iam_get_role",
                description="Get details for a specific IAM role",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "role_name": {
                            "type": "string",
                            "description": "Name of the role to retrieve"
                        }
                    },
                    "required": ["role_name"]
                }
            ),
            types.Tool(
                name="iam_get_policy",
                description="Get details for a specific IAM policy",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "policy_arn": {
                            "type": "string",
                            "description": "ARN of the policy to retrieve"
                        }
                    },
                    "required": ["policy_arn"]
                }
            ),
            types.Tool(
                name="iam_list_attached_user_policies",
                description="List policies attached to a specific user",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "user_name": {
                            "type": "string",
                            "description": "Name of the user"
                        },
                        "path_prefix": {
                            "type": "string",
                            "description": "The path prefix for filtering policies"
                        },
                        "max_items": {
                            "type": "integer",
                            "description": "Maximum number of policies to return",
                            "minimum": 1,
                            "maximum": 1000,
                            "default": 50
                        }
                    },
                    "required": ["user_name"]
                }
            ),
            types.Tool(
                name="iam_list_attached_role_policies",
                description="List policies attached to a specific role",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "role_name": {
                            "type": "string",
                            "description": "Name of the role"
                        },
                        "path_prefix": {
                            "type": "string",
                            "description": "The path prefix for filtering policies"
                        },
                        "max_items": {
                            "type": "integer",
                            "description": "Maximum number of policies to return",
                            "minimum": 1,
                            "maximum": 1000,
                            "default": 50
                        }
                    },
                    "required": ["role_name"]
                }
            ),
            types.Tool(
                name="iam_simulate_principal_policy",
                description="Simulate the effect of IAM policies on a resource",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "policy_source_arn": {
                            "type": "string",
                            "description": "ARN of the user or role to simulate"
                        },
                        "action_names": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of actions to simulate"
                        },
                        "resource_arns": {
                            "type": "array", 
                            "items": {"type": "string"},
                            "description": "List of resource ARNs to test against"
                        },
                        "context_entries": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "context_key_name": {"type": "string"},
                                    "context_key_values": {
                                        "type": "array",
                                        "items": {"type": "string"}
                                    },
                                    "context_key_type": {
                                        "type": "string",
                                        "enum": ["string", "stringList", "numeric", "numericList", "boolean", "booleanList", "ip", "ipList", "binary", "binaryList", "date", "dateList"]
                                    }
                                },
                                "required": ["context_key_name", "context_key_values", "context_key_type"]
                            },
                            "description": "Context entries for simulation"
                        }
                    },
                    "required": ["policy_source_arn", "action_names"]
                }
            ),
            types.Tool(
                name="iam_generate_credential_report",
                description="Generate IAM credential report for the account",
                inputSchema={
                    "type": "object",
                    "properties": {}
                }
            ),
            types.Tool(
                name="iam_get_credential_report",
                description="Get the most recent IAM credential report",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "format": {
                            "type": "string",
                            "enum": ["raw", "parsed"],
                            "description": "Format of the report (raw CSV or parsed JSON)",
                            "default": "parsed"
                        }
                    }
                }
            ),
            types.Tool(
                name="iam_get_users_not_accessed",
                description="Get IAM users that have not been accessed for a specified number of days",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "days_not_accessed": {
                            "type": "integer",
                            "description": "Number of days since last access",
                            "default": 60,
                            "minimum": 1
                        },
                        "include_never_accessed": {
                            "type": "boolean",
                            "description": "Include users who have never been accessed",
                            "default": True
                        }
                    }
                }
            ),
            types.Tool(
                name="iam_get_roles_not_accessed",
                description="Get IAM roles that have not been accessed for a specified number of days",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "days_not_accessed": {
                            "type": "integer",
                            "description": "Number of days since last access",
                            "default": 180,
                            "minimum": 1
                        },
                        "include_never_accessed": {
                            "type": "boolean",
                            "description": "Include roles that have never been accessed",
                            "default": True
                        },
                        "exclude_service_roles": {
                            "type": "boolean",
                            "description": "Exclude AWS service roles from results",
                            "default": True
                        }
                    }
                }
            ),
            types.Tool(
                name="iam_get_account_summary",
                description="Get IAM account summary with usage statistics",
                inputSchema={
                    "type": "object",
                    "properties": {}
                }
            )
        ]

    async def handle_tool_call(self, name: str, arguments: Dict[str, Any]) -> Any:
        """Handle IAM tool calls."""
        try:
            if name == "iam_list_users":
                return await self._list_users(arguments)
            elif name == "iam_list_roles":
                return await self._list_roles(arguments)
            elif name == "iam_list_policies":
                return await self._list_policies(arguments)
            elif name == "iam_get_user":
                return await self._get_user(arguments)
            elif name == "iam_get_role":
                return await self._get_role(arguments)
            elif name == "iam_get_policy":
                return await self._get_policy(arguments)
            elif name == "iam_list_attached_user_policies":
                return await self._list_attached_user_policies(arguments)
            elif name == "iam_list_attached_role_policies":
                return await self._list_attached_role_policies(arguments)
            elif name == "iam_simulate_principal_policy":
                return await self._simulate_principal_policy(arguments)
            elif name == "iam_generate_credential_report":
                return await self._generate_credential_report(arguments)
            elif name == "iam_get_credential_report":
                return await self._get_credential_report(arguments)
            elif name == "iam_get_users_not_accessed":
                return await self._get_users_not_accessed(arguments)
            elif name == "iam_get_roles_not_accessed":
                return await self._get_roles_not_accessed(arguments)
            elif name == "iam_get_account_summary":
                return await self._get_account_summary(arguments)
            else:
                raise ValueError(f"Unknown IAM tool: {name}")
                
        except ClientError as e:
            logger.error(f"AWS client error in {name}: {e}")
            return {"error": str(e), "service": "iam", "operation": name}
        except Exception as e:
            logger.error(f"Unexpected error in {name}: {e}")
            return {"error": str(e), "service": "iam", "operation": name}

    async def _list_users(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """List IAM users."""
        params = {}
        
        if "path_prefix" in arguments:
            params["PathPrefix"] = arguments["path_prefix"]
        if "marker" in arguments:
            params["Marker"] = arguments["marker"]
        if "max_items" in arguments:
            params["MaxItems"] = arguments["max_items"]
            
        response = self.client.list_users(**params)
        
        users = []
        for user in response.get("Users", []):
            users.append({
                "user_name": user["UserName"],
                "user_id": user["UserId"],
                "arn": user["Arn"],
                "path": user["Path"],
                "create_date": user["CreateDate"].isoformat(),
                "password_last_used": user.get("PasswordLastUsed", {}).isoformat() if user.get("PasswordLastUsed") else None,
                "permissions_boundary": user.get("PermissionsBoundary"),
                "tags": user.get("Tags", [])
            })
            
        return {
            "users": users,
            "is_truncated": response.get("IsTruncated", False),
            "marker": response.get("Marker")
        }

    async def _list_roles(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """List IAM roles."""
        params = {}
        
        if "path_prefix" in arguments:
            params["PathPrefix"] = arguments["path_prefix"]
        if "marker" in arguments:
            params["Marker"] = arguments["marker"]
        if "max_items" in arguments:
            params["MaxItems"] = arguments["max_items"]
            
        response = self.client.list_roles(**params)
        
        roles = []
        for role in response.get("Roles", []):
            roles.append({
                "role_name": role["RoleName"],
                "role_id": role["RoleId"],
                "arn": role["Arn"],
                "path": role["Path"],
                "create_date": role["CreateDate"].isoformat(),
                "assume_role_policy_document": role.get("AssumeRolePolicyDocument"),
                "description": role.get("Description"),
                "max_session_duration": role.get("MaxSessionDuration"),
                "permissions_boundary": role.get("PermissionsBoundary"),
                "tags": role.get("Tags", []),
                "role_last_used": role.get("RoleLastUsed")
            })
            
        return {
            "roles": roles,
            "is_truncated": response.get("IsTruncated", False),
            "marker": response.get("Marker")
        }

    async def _list_policies(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """List IAM policies."""
        params = {
            "Scope": arguments.get("scope", "Local"),
            "OnlyAttached": arguments.get("only_attached", False)
        }
        
        if "path_prefix" in arguments:
            params["PathPrefix"] = arguments["path_prefix"]
        if "policy_usage_filter" in arguments:
            params["PolicyUsageFilter"] = arguments["policy_usage_filter"]
        if "max_items" in arguments:
            params["MaxItems"] = arguments["max_items"]
            
        response = self.client.list_policies(**params)
        
        policies = []
        for policy in response.get("Policies", []):
            policies.append({
                "policy_name": policy["PolicyName"],
                "policy_id": policy["PolicyId"],
                "arn": policy["Arn"],
                "path": policy["Path"],
                "default_version_id": policy["DefaultVersionId"],
                "attachment_count": policy["AttachmentCount"],
                "permissions_boundary_usage_count": policy["PermissionsBoundaryUsageCount"],
                "is_attachable": policy["IsAttachable"],
                "description": policy.get("Description"),
                "create_date": policy["CreateDate"].isoformat(),
                "update_date": policy["UpdateDate"].isoformat(),
                "tags": policy.get("Tags", [])
            })
            
        return {
            "policies": policies,
            "is_truncated": response.get("IsTruncated", False),
            "marker": response.get("Marker")
        }

    async def _get_user(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get details for a specific user."""
        user_name = arguments["user_name"]
        response = self.client.get_user(UserName=user_name)
        
        user = response["User"]
        return {
            "user_name": user["UserName"],
            "user_id": user["UserId"],
            "arn": user["Arn"],
            "path": user["Path"],
            "create_date": user["CreateDate"].isoformat(),
            "password_last_used": user.get("PasswordLastUsed", {}).isoformat() if user.get("PasswordLastUsed") else None,
            "permissions_boundary": user.get("PermissionsBoundary"),
            "tags": user.get("Tags", [])
        }

    async def _get_role(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get details for a specific role."""
        role_name = arguments["role_name"]
        response = self.client.get_role(RoleName=role_name)
        
        role = response["Role"]
        return {
            "role_name": role["RoleName"],
            "role_id": role["RoleId"],
            "arn": role["Arn"],
            "path": role["Path"],
            "create_date": role["CreateDate"].isoformat(),
            "assume_role_policy_document": role.get("AssumeRolePolicyDocument"),
            "description": role.get("Description"),
            "max_session_duration": role.get("MaxSessionDuration"),
            "permissions_boundary": role.get("PermissionsBoundary"),
            "tags": role.get("Tags", []),
            "role_last_used": role.get("RoleLastUsed")
        }

    async def _get_policy(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get details for a specific policy."""
        policy_arn = arguments["policy_arn"]
        
        # Get policy metadata
        policy_response = self.client.get_policy(PolicyArn=policy_arn)
        policy = policy_response["Policy"]
        
        # Get policy version (document)
        version_response = self.client.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=policy["DefaultVersionId"]
        )
        
        return {
            "policy_name": policy["PolicyName"],
            "policy_id": policy["PolicyId"],
            "arn": policy["Arn"],
            "path": policy["Path"],
            "default_version_id": policy["DefaultVersionId"],
            "attachment_count": policy["AttachmentCount"],
            "permissions_boundary_usage_count": policy["PermissionsBoundaryUsageCount"],
            "is_attachable": policy["IsAttachable"],
            "description": policy.get("Description"),
            "create_date": policy["CreateDate"].isoformat(),
            "update_date": policy["UpdateDate"].isoformat(),
            "policy_document": version_response["PolicyVersion"]["Document"],
            "tags": policy.get("Tags", [])
        }

    async def _list_attached_user_policies(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """List policies attached to a user."""
        params = {"UserName": arguments["user_name"]}
        
        if "path_prefix" in arguments:
            params["PathPrefix"] = arguments["path_prefix"]
        if "max_items" in arguments:
            params["MaxItems"] = arguments["max_items"]
            
        response = self.client.list_attached_user_policies(**params)
        
        return {
            "attached_policies": response.get("AttachedPolicies", []),
            "is_truncated": response.get("IsTruncated", False),
            "marker": response.get("Marker")
        }

    async def _list_attached_role_policies(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """List policies attached to a role."""
        params = {"RoleName": arguments["role_name"]}
        
        if "path_prefix" in arguments:
            params["PathPrefix"] = arguments["path_prefix"]
        if "max_items" in arguments:
            params["MaxItems"] = arguments["max_items"]
            
        response = self.client.list_attached_role_policies(**params)
        
        return {
            "attached_policies": response.get("AttachedPolicies", []),
            "is_truncated": response.get("IsTruncated", False),
            "marker": response.get("Marker")
        }

    async def _simulate_principal_policy(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate principal policy evaluation."""
        params = {
            "PolicySourceArn": arguments["policy_source_arn"],
            "ActionNames": arguments["action_names"]
        }
        
        if "resource_arns" in arguments:
            params["ResourceArns"] = arguments["resource_arns"]
        if "context_entries" in arguments:
            params["ContextEntries"] = arguments["context_entries"]
            
        response = self.client.simulate_principal_policy(**params)
        
        return {
            "evaluation_results": response.get("EvaluationResults", []),
            "is_truncated": response.get("IsTruncated", False),
            "marker": response.get("Marker")
        }

    async def _generate_credential_report(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Generate IAM credential report."""
        response = self.client.generate_credential_report()
        
        return {
            "state": response.get("State"),
            "description": response.get("Description")
        }

    async def _get_credential_report(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get the most recent IAM credential report."""
        format_type = arguments.get("format", "parsed")
        
        try:
            response = self.client.get_credential_report()
            
            if format_type == "raw":
                # Return raw CSV content
                return {
                    "format": "raw",
                    "content": response["Content"].decode('utf-8'),
                    "generated_time": response["GeneratedTime"].isoformat(),
                    "report_format": response["ReportFormat"]
                }
            else:
                # Parse CSV and return structured data
                import csv
                import io
                
                csv_content = response["Content"].decode('utf-8')
                csv_reader = csv.DictReader(io.StringIO(csv_content))
                
                users = []
                for row in csv_reader:
                    users.append({
                        "user": row.get("user"),
                        "arn": row.get("arn"),
                        "user_creation_time": row.get("user_creation_time"),
                        "password_enabled": row.get("password_enabled") == "true",
                        "password_last_used": row.get("password_last_used"),
                        "password_last_changed": row.get("password_last_changed"),
                        "password_next_rotation": row.get("password_next_rotation"),
                        "mfa_active": row.get("mfa_active") == "true",
                        "access_key_1_active": row.get("access_key_1_active") == "true",
                        "access_key_1_last_rotated": row.get("access_key_1_last_rotated"),
                        "access_key_1_last_used_date": row.get("access_key_1_last_used_date"),
                        "access_key_1_last_used_region": row.get("access_key_1_last_used_region"),
                        "access_key_1_last_used_service": row.get("access_key_1_last_used_service"),
                        "access_key_2_active": row.get("access_key_2_active") == "true",
                        "access_key_2_last_rotated": row.get("access_key_2_last_rotated"),
                        "access_key_2_last_used_date": row.get("access_key_2_last_used_date"),
                        "access_key_2_last_used_region": row.get("access_key_2_last_used_region"),
                        "access_key_2_last_used_service": row.get("access_key_2_last_used_service"),
                        "cert_1_active": row.get("cert_1_active") == "true",
                        "cert_1_last_rotated": row.get("cert_1_last_rotated"),
                        "cert_2_active": row.get("cert_2_active") == "true",
                        "cert_2_last_rotated": row.get("cert_2_last_rotated")
                    })
                
                return {
                    "format": "parsed",
                    "users": users,
                    "total_users": len(users),
                    "generated_time": response["GeneratedTime"].isoformat(),
                    "report_format": response["ReportFormat"]
                }
                
        except ClientError as e:
            if e.response["Error"]["Code"] == "ReportNotPresent":
                return {"error": "No credential report available. Generate one first using iam_generate_credential_report"}
            raise

    async def _get_users_not_accessed(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get IAM users that have not been accessed for a specified number of days."""
        from datetime import datetime, timedelta
        
        days_not_accessed = arguments.get("days_not_accessed", 60)
        include_never_accessed = arguments.get("include_never_accessed", True)
        
        cutoff_date = datetime.utcnow() - timedelta(days=days_not_accessed)
        
        # Get all users
        all_users = []
        marker = None
        
        while True:
            params = {"MaxItems": 1000}
            if marker:
                params["Marker"] = marker
                
            response = self.client.list_users(**params)
            all_users.extend(response.get("Users", []))
            
            if not response.get("IsTruncated", False):
                break
            marker = response.get("Marker")
        
        inactive_users = []
        
        for user in all_users:
            user_name = user["UserName"]
            password_last_used = user.get("PasswordLastUsed")
            
            # Check access keys
            try:
                keys_response = self.client.list_access_keys(UserName=user_name)
                
                latest_access = None
                
                # Check password last used
                if password_last_used:
                    latest_access = password_last_used
                
                # Check access key usage
                for key in keys_response.get("AccessKeyMetadata", []):
                    if key.get("Status") == "Active":
                        try:
                            usage_response = self.client.get_access_key_last_used(
                                AccessKeyId=key["AccessKeyId"]
                            )
                            
                            key_last_used = usage_response.get("AccessKeyLastUsed", {}).get("LastUsedDate")
                            if key_last_used:
                                if not latest_access or key_last_used > latest_access:
                                    latest_access = key_last_used
                        except ClientError:
                            # Skip if we can't get usage info
                            pass
                
                # Determine if user should be included
                should_include = False
                never_accessed = latest_access is None
                
                if never_accessed and include_never_accessed:
                    should_include = True
                elif latest_access and latest_access < cutoff_date:
                    should_include = True
                
                if should_include:
                    inactive_users.append({
                        "user_name": user_name,
                        "user_id": user["UserId"],
                        "arn": user["Arn"],
                        "path": user["Path"],
                        "created_date": user["CreateDate"].isoformat(),
                        "last_access_date": latest_access.isoformat() if latest_access else None,
                        "days_since_last_access": (datetime.utcnow() - latest_access).days if latest_access else None,
                        "never_accessed": never_accessed,
                        "tags": user.get("Tags", [])
                    })
                    
            except ClientError as e:
                logger.warning(f"Could not check access for user {user_name}: {e}")
        
        return {
            "inactive_users": inactive_users,
            "total_inactive": len(inactive_users),
            "total_users_checked": len(all_users),
            "criteria": {
                "days_not_accessed": days_not_accessed,
                "include_never_accessed": include_never_accessed,
                "cutoff_date": cutoff_date.isoformat()
            }
        }

    async def _get_roles_not_accessed(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get IAM roles that have not been accessed for a specified number of days."""
        from datetime import datetime, timedelta
        
        days_not_accessed = arguments.get("days_not_accessed", 180)
        include_never_accessed = arguments.get("include_never_accessed", True)
        exclude_service_roles = arguments.get("exclude_service_roles", True)
        
        cutoff_date = datetime.utcnow() - timedelta(days=days_not_accessed)
        
        # Get all roles
        all_roles = []
        marker = None
        
        while True:
            params = {"MaxItems": 1000}
            if marker:
                params["Marker"] = marker
                
            response = self.client.list_roles(**params)
            all_roles.extend(response.get("Roles", []))
            
            if not response.get("IsTruncated", False):
                break
            marker = response.get("Marker")
        
        inactive_roles = []
        
        for role in all_roles:
            role_name = role["RoleName"]
            role_last_used = role.get("RoleLastUsed", {})
            last_used_date = role_last_used.get("LastUsedDate")
            
            # Skip AWS service roles if requested
            if exclude_service_roles:
                assume_role_policy = role.get("AssumeRolePolicyDocument", {})
                if isinstance(assume_role_policy, str):
                    import json
                    try:
                        assume_role_policy = json.loads(assume_role_policy)
                    except json.JSONDecodeError:
                        pass
                
                # Check if it's a service role
                if isinstance(assume_role_policy, dict):
                    statements = assume_role_policy.get("Statement", [])
                    for statement in statements:
                        if isinstance(statement, dict):
                            principal = statement.get("Principal", {})
                            if isinstance(principal, dict) and "Service" in principal:
                                # This is likely a service role, skip it
                                continue
            
            # Determine if role should be included
            should_include = False
            never_accessed = last_used_date is None
            
            if never_accessed and include_never_accessed:
                should_include = True
            elif last_used_date and last_used_date < cutoff_date:
                should_include = True
            
            if should_include:
                inactive_roles.append({
                    "role_name": role_name,
                    "role_id": role["RoleId"],
                    "arn": role["Arn"],
                    "path": role["Path"],
                    "created_date": role["CreateDate"].isoformat(),
                    "last_used_date": last_used_date.isoformat() if last_used_date else None,
                    "last_used_region": role_last_used.get("Region"),
                    "days_since_last_use": (datetime.utcnow() - last_used_date).days if last_used_date else None,
                    "never_accessed": never_accessed,
                    "description": role.get("Description"),
                    "max_session_duration": role.get("MaxSessionDuration"),
                    "tags": role.get("Tags", [])
                })
        
        return {
            "inactive_roles": inactive_roles,
            "total_inactive": len(inactive_roles),
            "total_roles_checked": len(all_roles),
            "criteria": {
                "days_not_accessed": days_not_accessed,
                "include_never_accessed": include_never_accessed,
                "exclude_service_roles": exclude_service_roles,
                "cutoff_date": cutoff_date.isoformat()
            }
        }

    async def _get_account_summary(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get IAM account summary with usage statistics."""
        response = self.client.get_account_summary()
        
        summary_map = response.get("SummaryMap", {})
        
        return {
            "users": summary_map.get("Users", 0),
            "users_quota": summary_map.get("UsersQuota", 0),
            "groups": summary_map.get("Groups", 0),
            "groups_quota": summary_map.get("GroupsQuota", 0),
            "roles": summary_map.get("Roles", 0),
            "roles_quota": summary_map.get("RolesQuota", 0),
            "policies": summary_map.get("Policies", 0),
            "policies_quota": summary_map.get("PoliciesQuota", 0),
            "instance_profiles": summary_map.get("InstanceProfiles", 0),
            "instance_profiles_quota": summary_map.get("InstanceProfilesQuota", 0),
            "server_certificates": summary_map.get("ServerCertificates", 0),
            "server_certificates_quota": summary_map.get("ServerCertificatesQuota", 0),
            "account_mfa_enabled": summary_map.get("AccountMFAEnabled", 0),
            "account_access_keys_present": summary_map.get("AccountAccessKeysPresent", 0),
            "account_signing_certificates_present": summary_map.get("AccountSigningCertificatesPresent", 0),
            "attached_policies_per_group_quota": summary_map.get("AttachedPoliciesPerGroupQuota", 0),
            "attached_policies_per_role_quota": summary_map.get("AttachedPoliciesPerRoleQuota", 0),
            "attached_policies_per_user_quota": summary_map.get("AttachedPoliciesPerUserQuota", 0),
            "global_endpoint_token_version": summary_map.get("GlobalEndpointTokenVersion", 0),
            "versions_per_policy_quota": summary_map.get("VersionsPerPolicyQuota", 0),
            "policy_size_quota": summary_map.get("PolicySizeQuota", 0),
            "policy_versions_in_use": summary_map.get("PolicyVersionsInUse", 0),
            "policy_versions_in_use_quota": summary_map.get("PolicyVersionsInUseQuota", 0)
        }
