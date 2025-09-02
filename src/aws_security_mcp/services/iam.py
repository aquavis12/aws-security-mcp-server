"""Clean IAM service implementation for AWS Security MCP Server."""

import json
import logging
from typing import Any, Dict, List
from datetime import datetime, timedelta

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
                        "max_items": {
                            "type": "integer",
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
                        "max_items": {
                            "type": "integer",
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
                            "default": "Local"
                        },
                        "max_items": {
                            "type": "integer",
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
                            "description": "Name of the user"
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
                            "description": "Name of the role"
                        }
                    },
                    "required": ["role_name"]
                }
            ),
            types.Tool(
                name="iam_get_policy",
                description="Get IAM policy details including document",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "policy_arn": {
                            "type": "string",
                            "description": "ARN of the policy"
                        }
                    },
                    "required": ["policy_arn"]
                }
            ),
            types.Tool(
                name="iam_list_attached_user_policies",
                description="List policies attached to a user",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "user_name": {
                            "type": "string",
                            "description": "Name of the user"
                        }
                    },
                    "required": ["user_name"]
                }
            ),
            types.Tool(
                name="iam_list_attached_role_policies",
                description="List policies attached to a role",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "role_name": {
                            "type": "string",
                            "description": "Name of the role"
                        }
                    },
                    "required": ["role_name"]
                }
            ),
            types.Tool(
                name="iam_get_credential_report",
                description="Get IAM credential report",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "format": {
                            "type": "string",
                            "enum": ["raw", "parsed"],
                            "default": "parsed"
                        }
                    }
                }
            ),
            types.Tool(
                name="iam_get_users_not_accessed",
                description="Get users not accessed for specified days",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "days_not_accessed": {
                            "type": "integer",
                            "minimum": 1,
                            "default": 60
                        }
                    }
                }
            ),
            types.Tool(
                name="iam_get_account_summary",
                description="Get IAM account summary",
                inputSchema={
                    "type": "object",
                    "properties": {}
                }
            ),
            types.Tool(
                name="iam_audit_inactive_users",
                description="Audit IAM users inactive for specified days",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "days_inactive": {
                            "type": "integer",
                            "minimum": 1,
                            "default": 90,
                            "description": "Days of inactivity threshold"
                        }
                    }
                }
            ),
            types.Tool(
                name="iam_audit_unrotated_keys",
                description="Find access keys not rotated for specified days",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "days_old": {
                            "type": "integer",
                            "minimum": 1,
                            "default": 180,
                            "description": "Age threshold for key rotation"
                        }
                    }
                }
            ),
            types.Tool(
                name="iam_audit_overprivileged_policies",
                description="Identify overprivileged IAM policies",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "check_admin_policies": {
                            "type": "boolean",
                            "default": True,
                            "description": "Check for admin-level policies"
                        },
                        "check_wildcard_resources": {
                            "type": "boolean",
                            "default": True,
                            "description": "Check for wildcard resource policies"
                        }
                    }
                }
            ),
            types.Tool(
                name="iam_audit_mfa_status",
                description="Audit MFA status for all users",
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
            elif name == "iam_get_credential_report":
                return await self._get_credential_report(arguments)
            elif name == "iam_get_users_not_accessed":
                return await self._get_users_not_accessed(arguments)
            elif name == "iam_get_account_summary":
                return await self._get_account_summary(arguments)
            elif name == "iam_audit_inactive_users":
                return await self._audit_inactive_users(arguments)
            elif name == "iam_audit_unrotated_keys":
                return await self._audit_unrotated_keys(arguments)
            elif name == "iam_audit_overprivileged_policies":
                return await self._audit_overprivileged_policies(arguments)
            elif name == "iam_audit_mfa_status":
                return await self._audit_mfa_status(arguments)
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
            "Scope": arguments.get("scope", "Local")
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
        """Get user details."""
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

    async def _get_role(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get role details."""
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
            "tags": role.get("Tags", [])
        }

    async def _get_policy(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get policy details."""
        policy_arn = arguments["policy_arn"]
        
        policy_response = self.client.get_policy(PolicyArn=policy_arn)
        policy = policy_response["Policy"]
        
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
            "is_attachable": policy["IsAttachable"],
            "description": policy.get("Description"),
            "create_date": policy["CreateDate"].isoformat(),
            "update_date": policy["UpdateDate"].isoformat(),
            "policy_document": version_response["PolicyVersion"]["Document"]
        }

    async def _list_attached_user_policies(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """List attached user policies."""
        user_name = arguments["user_name"]
        response = self.client.list_attached_user_policies(UserName=user_name)
        
        return {
            "attached_policies": response.get("AttachedPolicies", []),
            "is_truncated": response.get("IsTruncated", False)
        }

    async def _list_attached_role_policies(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """List attached role policies."""
        role_name = arguments["role_name"]
        response = self.client.list_attached_role_policies(RoleName=role_name)
        
        return {
            "attached_policies": response.get("AttachedPolicies", []),
            "is_truncated": response.get("IsTruncated", False)
        }

    async def _get_credential_report(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get credential report."""
        format_type = arguments.get("format", "parsed")
        
        try:
            response = self.client.get_credential_report()
            
            if format_type == "raw":
                return {
                    "format": "raw",
                    "content": response["Content"].decode('utf-8'),
                    "generated_time": response["GeneratedTime"].isoformat()
                }
            else:
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
                        "mfa_active": row.get("mfa_active") == "true",
                        "access_key_1_active": row.get("access_key_1_active") == "true",
                        "access_key_1_last_used_date": row.get("access_key_1_last_used_date"),
                        "access_key_2_active": row.get("access_key_2_active") == "true",
                        "access_key_2_last_used_date": row.get("access_key_2_last_used_date")
                    })
                
                return {
                    "format": "parsed",
                    "users": users,
                    "total_users": len(users),
                    "generated_time": response["GeneratedTime"].isoformat()
                }
                
        except ClientError as e:
            if e.response["Error"]["Code"] == "ReportNotPresent":
                return {"error": "No credential report available. Generate one first."}
            raise

    async def _get_users_not_accessed(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get users not accessed for specified days."""
        days_not_accessed = arguments.get("days_not_accessed", 60)
        cutoff_date = datetime.utcnow() - timedelta(days=days_not_accessed)
        
        response = self.client.list_users(MaxItems=1000)
        inactive_users = []
        
        for user in response.get("Users", []):
            user_name = user["UserName"]
            password_last_used = user.get("PasswordLastUsed")
            
            latest_access = password_last_used
            
            # Check access keys
            try:
                keys_response = self.client.list_access_keys(UserName=user_name)
                for key in keys_response.get("AccessKeyMetadata", []):
                    if key.get("Status") == "Active":
                        try:
                            usage_response = self.client.get_access_key_last_used(
                                AccessKeyId=key["AccessKeyId"]
                            )
                            key_last_used = usage_response.get("AccessKeyLastUsed", {}).get("LastUsedDate")
                            if key_last_used and (not latest_access or key_last_used > latest_access):
                                latest_access = key_last_used
                        except ClientError:
                            pass
            except ClientError:
                pass
            
            if not latest_access or latest_access < cutoff_date:
                inactive_users.append({
                    "user_name": user_name,
                    "arn": user["Arn"],
                    "created_date": user["CreateDate"].isoformat(),
                    "last_access_date": latest_access.isoformat() if latest_access else None,
                    "days_since_last_access": (datetime.utcnow() - latest_access).days if latest_access else None,
                    "never_accessed": latest_access is None
                })
        
        return {
            "inactive_users": inactive_users,
            "total_inactive": len(inactive_users),
            "criteria": {
                "days_not_accessed": days_not_accessed,
                "cutoff_date": cutoff_date.isoformat()
            }
        }

    async def _get_account_summary(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get account summary."""
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
            "account_mfa_enabled": summary_map.get("AccountMFAEnabled", 0)
        }

    async def _audit_inactive_users(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Audit inactive users."""
        days_inactive = arguments.get("days_inactive", 90)
        cutoff_date = datetime.utcnow() - timedelta(days=days_inactive)
        
        response = self.client.list_users(MaxItems=1000)
        inactive_users = []
        
        for user in response.get("Users", []):
            user_name = user["UserName"]
            password_last_used = user.get("PasswordLastUsed")
            latest_access = password_last_used
            
            # Check access keys
            try:
                keys_response = self.client.list_access_keys(UserName=user_name)
                for key in keys_response.get("AccessKeyMetadata", []):
                    if key.get("Status") == "Active":
                        try:
                            usage_response = self.client.get_access_key_last_used(
                                AccessKeyId=key["AccessKeyId"]
                            )
                            key_last_used = usage_response.get("AccessKeyLastUsed", {}).get("LastUsedDate")
                            if key_last_used and (not latest_access or key_last_used > latest_access):
                                latest_access = key_last_used
                        except ClientError:
                            pass
            except ClientError:
                pass
            
            if not latest_access or latest_access < cutoff_date:
                inactive_users.append({
                    "user_name": user_name,
                    "arn": user["Arn"],
                    "created_date": user["CreateDate"].isoformat(),
                    "last_access_date": latest_access.isoformat() if latest_access else None,
                    "days_inactive": (datetime.utcnow() - latest_access).days if latest_access else None,
                    "never_accessed": latest_access is None,
                    "risk_level": "HIGH" if not latest_access else "MEDIUM"
                })
        
        return {
            "inactive_users": inactive_users,
            "total_inactive": len(inactive_users),
            "audit_criteria": {"days_inactive": days_inactive}
        }

    async def _audit_unrotated_keys(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Audit unrotated access keys."""
        days_old = arguments.get("days_old", 180)
        cutoff_date = datetime.utcnow() - timedelta(days=days_old)
        
        response = self.client.list_users(MaxItems=1000)
        old_keys = []
        
        for user in response.get("Users", []):
            user_name = user["UserName"]
            
            try:
                keys_response = self.client.list_access_keys(UserName=user_name)
                for key in keys_response.get("AccessKeyMetadata", []):
                    if key.get("Status") == "Active" and key.get("CreateDate") < cutoff_date:
                        age_days = (datetime.utcnow() - key["CreateDate"]).days
                        old_keys.append({
                            "user_name": user_name,
                            "access_key_id": key["AccessKeyId"],
                            "created_date": key["CreateDate"].isoformat(),
                            "age_days": age_days,
                            "status": key["Status"],
                            "risk_level": "CRITICAL" if age_days > 365 else "HIGH"
                        })
            except ClientError:
                pass
        
        return {
            "old_access_keys": old_keys,
            "total_old_keys": len(old_keys),
            "audit_criteria": {"days_old": days_old}
        }

    async def _audit_overprivileged_policies(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Audit overprivileged policies."""
        check_admin = arguments.get("check_admin_policies", True)
        check_wildcards = arguments.get("check_wildcard_resources", True)
        
        response = self.client.list_policies(Scope="Local", MaxItems=1000)
        risky_policies = []
        
        for policy in response.get("Policies", []):
            if policy["AttachmentCount"] > 0:  # Only check attached policies
                try:
                    version_response = self.client.get_policy_version(
                        PolicyArn=policy["Arn"],
                        VersionId=policy["DefaultVersionId"]
                    )
                    
                    policy_doc = version_response["PolicyVersion"]["Document"]
                    if isinstance(policy_doc, str):
                        policy_doc = json.loads(policy_doc)
                    
                    risk_factors = []
                    risk_level = "LOW"
                    
                    for statement in policy_doc.get("Statement", []):
                        if isinstance(statement, dict):
                            actions = statement.get("Action", [])
                            resources = statement.get("Resource", [])
                            effect = statement.get("Effect", "")
                            
                            if effect == "Allow":
                                # Check for admin actions
                                if check_admin and ("*" in actions or "*:*" in actions):
                                    risk_factors.append("Full admin access (Action: *)")
                                    risk_level = "CRITICAL"
                                
                                # Check for wildcard resources
                                if check_wildcards and "*" in resources:
                                    risk_factors.append("Wildcard resources (Resource: *)")
                                    if risk_level != "CRITICAL":
                                        risk_level = "HIGH"
                                
                                # Check for dangerous actions
                                dangerous_actions = [
                                    "iam:*", "s3:*", "ec2:*", "rds:*",
                                    "iam:CreateUser", "iam:CreateRole", "iam:AttachUserPolicy"
                                ]
                                for action in actions:
                                    if action in dangerous_actions:
                                        risk_factors.append(f"Dangerous action: {action}")
                                        if risk_level == "LOW":
                                            risk_level = "MEDIUM"
                    
                    if risk_factors:
                        risky_policies.append({
                            "policy_name": policy["PolicyName"],
                            "policy_arn": policy["Arn"],
                            "attachment_count": policy["AttachmentCount"],
                            "risk_level": risk_level,
                            "risk_factors": risk_factors,
                            "created_date": policy["CreateDate"].isoformat()
                        })
                        
                except (ClientError, json.JSONDecodeError):
                    pass
        
        return {
            "risky_policies": risky_policies,
            "total_risky_policies": len(risky_policies),
            "audit_criteria": {
                "check_admin_policies": check_admin,
                "check_wildcard_resources": check_wildcards
            }
        }

    async def _audit_mfa_status(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Audit MFA status for all users."""
        response = self.client.list_users(MaxItems=1000)
        mfa_status = []
        
        for user in response.get("Users", []):
            user_name = user["UserName"]
            
            try:
                # Check for MFA devices
                mfa_response = self.client.list_mfa_devices(UserName=user_name)
                virtual_mfa_response = self.client.list_virtual_mfa_devices()
                
                has_mfa = len(mfa_response.get("MFADevices", [])) > 0
                
                # Check virtual MFA devices
                for virtual_device in virtual_mfa_response.get("VirtualMFADevices", []):
                    if virtual_device.get("User", {}).get("UserName") == user_name:
                        has_mfa = True
                        break
                
                # Check if user has console access
                has_console_access = False
                try:
                    self.client.get_login_profile(UserName=user_name)
                    has_console_access = True
                except ClientError as e:
                    if e.response["Error"]["Code"] != "NoSuchEntity":
                        pass
                
                risk_level = "LOW"
                if has_console_access and not has_mfa:
                    risk_level = "HIGH"
                elif not has_mfa:
                    risk_level = "MEDIUM"
                
                mfa_status.append({
                    "user_name": user_name,
                    "arn": user["Arn"],
                    "has_mfa": has_mfa,
                    "has_console_access": has_console_access,
                    "risk_level": risk_level,
                    "created_date": user["CreateDate"].isoformat()
                })
                
            except ClientError:
                pass
        
        users_without_mfa = [u for u in mfa_status if not u["has_mfa"]]
        console_users_without_mfa = [u for u in users_without_mfa if u["has_console_access"]]
        
        return {
            "mfa_status": mfa_status,
            "users_without_mfa": users_without_mfa,
            "console_users_without_mfa": console_users_without_mfa,
            "total_users": len(mfa_status),
            "total_without_mfa": len(users_without_mfa),
            "high_risk_users": len(console_users_without_mfa)
        }