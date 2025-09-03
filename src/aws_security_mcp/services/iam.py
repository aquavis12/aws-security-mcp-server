"""Simplified IAM service to prevent continue prompts."""

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
        """Get available IAM tools with minimal schemas."""
        return [
            types.Tool(
                name="iam_list_users",
                description="List IAM users in the account",
                inputSchema={"type": "object", "properties": {}}
            ),
            types.Tool(
                name="iam_list_roles", 
                description="List IAM roles in the account",
                inputSchema={"type": "object", "properties": {}}
            ),
            types.Tool(
                name="iam_list_policies",
                description="List IAM policies in the account", 
                inputSchema={"type": "object", "properties": {}}
            ),
            types.Tool(
                name="iam_get_user",
                description="Get details for a specific IAM user",
                inputSchema={"type": "object", "properties": {"user_name": {"type": "string"}}, "required": ["user_name"]}
            ),
            types.Tool(
                name="iam_get_role",
                description="Get details for a specific IAM role",
                inputSchema={"type": "object", "properties": {"role_name": {"type": "string"}}, "required": ["role_name"]}
            ),
            types.Tool(
                name="iam_get_policy",
                description="Get IAM policy details including document",
                inputSchema={"type": "object", "properties": {"policy_arn": {"type": "string"}}, "required": ["policy_arn"]}
            ),
            types.Tool(
                name="iam_list_attached_user_policies",
                description="List policies attached to a user",
                inputSchema={"type": "object", "properties": {"user_name": {"type": "string"}}, "required": ["user_name"]}
            ),
            types.Tool(
                name="iam_list_attached_role_policies", 
                description="List policies attached to a role",
                inputSchema={"type": "object", "properties": {"role_name": {"type": "string"}}, "required": ["role_name"]}
            ),
            types.Tool(
                name="iam_get_credential_report",
                description="Get IAM credential report",
                inputSchema={"type": "object", "properties": {}}
            ),
            types.Tool(
                name="iam_get_users_not_accessed",
                description="Get users not accessed for 60+ days",
                inputSchema={"type": "object", "properties": {}}
            ),
            types.Tool(
                name="iam_get_account_summary",
                description="Get IAM account summary",
                inputSchema={"type": "object", "properties": {}}
            ),
            types.Tool(
                name="iam_audit_inactive_users",
                description="Audit IAM users inactive for 90+ days",
                inputSchema={"type": "object", "properties": {}}
            ),
            types.Tool(
                name="iam_audit_unrotated_keys",
                description="Find access keys not rotated for 180+ days",
                inputSchema={"type": "object", "properties": {}}
            ),
            types.Tool(
                name="iam_audit_overprivileged_policies",
                description="Identify overprivileged IAM policies",
                inputSchema={"type": "object", "properties": {}}
            ),
            types.Tool(
                name="iam_audit_mfa_status",
                description="Audit MFA status for all users",
                inputSchema={"type": "object", "properties": {}}
            )
        ]

    async def handle_tool_call(self, name: str, arguments: Dict[str, Any]) -> Any:
        """Handle IAM tool calls."""
        try:
            if name == "iam_list_users":
                return await self._list_users()
            elif name == "iam_list_roles":
                return await self._list_roles()
            elif name == "iam_list_policies":
                return await self._list_policies()
            elif name == "iam_get_user":
                return await self._get_user(arguments["user_name"])
            elif name == "iam_get_role":
                return await self._get_role(arguments["role_name"])
            elif name == "iam_get_policy":
                return await self._get_policy(arguments["policy_arn"])
            elif name == "iam_list_attached_user_policies":
                return await self._list_attached_user_policies(arguments["user_name"])
            elif name == "iam_list_attached_role_policies":
                return await self._list_attached_role_policies(arguments["role_name"])
            elif name == "iam_get_credential_report":
                return await self._get_credential_report()
            elif name == "iam_get_users_not_accessed":
                return await self._get_users_not_accessed()
            elif name == "iam_get_account_summary":
                return await self._get_account_summary()
            elif name == "iam_audit_inactive_users":
                return await self._audit_inactive_users()
            elif name == "iam_audit_unrotated_keys":
                return await self._audit_unrotated_keys()
            elif name == "iam_audit_overprivileged_policies":
                return await self._audit_overprivileged_policies()
            elif name == "iam_audit_mfa_status":
                return await self._audit_mfa_status()
            else:
                raise ValueError(f"Unknown IAM tool: {name}")
        except ClientError as e:
            return {"error": str(e), "service": "iam"}
        except Exception as e:
            return {"error": str(e), "service": "iam"}

    async def _list_users(self) -> Dict[str, Any]:
        """List IAM users."""
        response = self.client.list_users(MaxItems=50)
        return {"users": response.get("Users", [])}

    async def _list_roles(self) -> Dict[str, Any]:
        """List IAM roles."""
        response = self.client.list_roles(MaxItems=50)
        return {"roles": response.get("Roles", [])}

    async def _list_policies(self) -> Dict[str, Any]:
        """List IAM policies."""
        response = self.client.list_policies(Scope="Local", MaxItems=50)
        return {"policies": response.get("Policies", [])}

    async def _get_user(self, user_name: str) -> Dict[str, Any]:
        """Get user details."""
        response = self.client.get_user(UserName=user_name)
        return {"user": response["User"]}

    async def _get_role(self, role_name: str) -> Dict[str, Any]:
        """Get role details."""
        response = self.client.get_role(RoleName=role_name)
        return {"role": response["Role"]}

    async def _get_policy(self, policy_arn: str) -> Dict[str, Any]:
        """Get policy details."""
        response = self.client.get_policy(PolicyArn=policy_arn)
        return {"policy": response["Policy"]}

    async def _list_attached_user_policies(self, user_name: str) -> Dict[str, Any]:
        """List attached user policies."""
        response = self.client.list_attached_user_policies(UserName=user_name)
        return {"attached_policies": response.get("AttachedPolicies", [])}

    async def _list_attached_role_policies(self, role_name: str) -> Dict[str, Any]:
        """List attached role policies."""
        response = self.client.list_attached_role_policies(RoleName=role_name)
        return {"attached_policies": response.get("AttachedPolicies", [])}

    async def _get_credential_report(self) -> Dict[str, Any]:
        """Get credential report."""
        try:
            response = self.client.get_credential_report()
            return {"report_available": True, "generated_time": response["GeneratedTime"].isoformat()}
        except ClientError:
            return {"report_available": False, "message": "Generate credential report first"}

    async def _get_users_not_accessed(self) -> Dict[str, Any]:
        """Get users not accessed for 60+ days."""
        cutoff_date = datetime.utcnow() - timedelta(days=60)
        response = self.client.list_users(MaxItems=100)
        inactive_users = []
        
        for user in response.get("Users", []):
            last_used = user.get("PasswordLastUsed")
            if not last_used or last_used < cutoff_date:
                inactive_users.append(user["UserName"])
        
        return {"inactive_users": inactive_users, "total": len(inactive_users)}

    async def _get_account_summary(self) -> Dict[str, Any]:
        """Get account summary."""
        response = self.client.get_account_summary()
        return {"summary": response.get("SummaryMap", {})}

    async def _audit_inactive_users(self) -> Dict[str, Any]:
        """Audit inactive users (90+ days)."""
        cutoff_date = datetime.utcnow() - timedelta(days=90)
        response = self.client.list_users(MaxItems=100)
        inactive_users = []
        
        for user in response.get("Users", []):
            last_used = user.get("PasswordLastUsed")
            if not last_used or last_used < cutoff_date:
                inactive_users.append({
                    "user_name": user["UserName"],
                    "last_used": last_used.isoformat() if last_used else "Never",
                    "risk": "HIGH" if not last_used else "MEDIUM"
                })
        
        return {"inactive_users": inactive_users, "total": len(inactive_users)}

    async def _audit_unrotated_keys(self) -> Dict[str, Any]:
        """Audit unrotated access keys (180+ days)."""
        cutoff_date = datetime.utcnow() - timedelta(days=180)
        response = self.client.list_users(MaxItems=100)
        old_keys = []
        
        for user in response.get("Users", []):
            try:
                keys_response = self.client.list_access_keys(UserName=user["UserName"])
                for key in keys_response.get("AccessKeyMetadata", []):
                    if key["Status"] == "Active" and key["CreateDate"] < cutoff_date:
                        old_keys.append({
                            "user_name": user["UserName"],
                            "access_key_id": key["AccessKeyId"],
                            "age_days": (datetime.utcnow() - key["CreateDate"]).days
                        })
            except ClientError:
                pass
        
        return {"old_keys": old_keys, "total": len(old_keys)}

    async def _audit_overprivileged_policies(self) -> Dict[str, Any]:
        """Audit overprivileged policies."""
        response = self.client.list_policies(Scope="Local", MaxItems=50)
        risky_policies = []
        
        for policy in response.get("Policies", []):
            if policy["AttachmentCount"] > 0:
                try:
                    version_response = self.client.get_policy_version(
                        PolicyArn=policy["Arn"],
                        VersionId=policy["DefaultVersionId"]
                    )
                    doc = version_response["PolicyVersion"]["Document"]
                    if isinstance(doc, str):
                        doc = json.loads(doc)
                    
                    for statement in doc.get("Statement", []):
                        actions = statement.get("Action", [])
                        if "*" in actions or "*:*" in actions:
                            risky_policies.append({
                                "policy_name": policy["PolicyName"],
                                "risk": "CRITICAL - Full admin access"
                            })
                            break
                except (ClientError, json.JSONDecodeError):
                    pass
        
        return {"risky_policies": risky_policies, "total": len(risky_policies)}

    async def _audit_mfa_status(self) -> Dict[str, Any]:
        """Audit MFA status for all users."""
        response = self.client.list_users(MaxItems=100)
        users_without_mfa = []
        
        for user in response.get("Users", []):
            try:
                mfa_response = self.client.list_mfa_devices(UserName=user["UserName"])
                if not mfa_response.get("MFADevices"):
                    users_without_mfa.append({
                        "user_name": user["UserName"],
                        "risk": "HIGH - No MFA enabled"
                    })
            except ClientError:
                pass
        
        return {"users_without_mfa": users_without_mfa, "total": len(users_without_mfa)}