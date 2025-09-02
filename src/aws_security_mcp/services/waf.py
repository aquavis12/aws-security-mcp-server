"""WAF service implementation for AWS Security MCP Server."""

import logging
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError
import mcp.types as types

logger = logging.getLogger(__name__)


class WAFService:
    """Service for handling WAF operations."""

    def __init__(self, session: boto3.Session):
        """Initialize the WAF service."""
        self.client = session.client("wafv2")

    def get_tools(self) -> List[types.Tool]:
        """Get available WAF tools."""
        return [
            types.Tool(
                name="waf_list_web_acls",
                description="List WAF Web ACLs",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "scope": {
                            "type": "string",
                            "enum": ["CLOUDFRONT", "REGIONAL"],
                            "description": "Scope of the Web ACL",
                            "default": "REGIONAL"
                        },
                        "limit": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 100,
                            "default": 50
                        }
                    }
                }
            ),
            types.Tool(
                name="waf_get_web_acl",
                description="Get details for a specific Web ACL",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string",
                            "description": "Name of the Web ACL"
                        },
                        "scope": {
                            "type": "string",
                            "enum": ["CLOUDFRONT", "REGIONAL"],
                            "description": "Scope of the Web ACL",
                            "default": "REGIONAL"
                        },
                        "id": {
                            "type": "string",
                            "description": "ID of the Web ACL"
                        }
                    },
                    "required": ["name", "scope", "id"]
                }
            ),
            types.Tool(
                name="waf_list_ip_sets",
                description="List WAF IP sets",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "scope": {
                            "type": "string",
                            "enum": ["CLOUDFRONT", "REGIONAL"],
                            "description": "Scope of the IP sets",
                            "default": "REGIONAL"
                        },
                        "limit": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 100,
                            "default": 50
                        }
                    }
                }
            ),
            types.Tool(
                name="waf_list_rule_groups",
                description="List WAF rule groups",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "scope": {
                            "type": "string",
                            "enum": ["CLOUDFRONT", "REGIONAL"],
                            "description": "Scope of the rule groups",
                            "default": "REGIONAL"
                        },
                        "limit": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 100,
                            "default": 50
                        }
                    }
                }
            )
        ]

    async def handle_tool_call(self, name: str, arguments: Dict[str, Any]) -> Any:
        """Handle WAF tool calls."""
        try:
            if name == "waf_list_web_acls":
                return await self._list_web_acls(arguments)
            elif name == "waf_get_web_acl":
                return await self._get_web_acl(arguments)
            elif name == "waf_list_ip_sets":
                return await self._list_ip_sets(arguments)
            elif name == "waf_list_rule_groups":
                return await self._list_rule_groups(arguments)
            else:
                raise ValueError(f"Unknown WAF tool: {name}")

        except ClientError as e:
            logger.error(f"AWS client error in {name}: {e}")
            return {"error": str(e), "service": "waf", "operation": name}
        except Exception as e:
            logger.error(f"Unexpected error in {name}: {e}")
            return {"error": str(e), "service": "waf", "operation": name}

    async def _list_web_acls(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """List WAF Web ACLs."""
        params = {
            "Scope": arguments.get("scope", "REGIONAL")
        }
        if "limit" in arguments:
            params["Limit"] = arguments["limit"]

        response = self.client.list_web_acls(**params)
        
        web_acls = []
        for web_acl in response.get("WebACLs", []):
            web_acls.append({
                "name": web_acl.get("Name"),
                "id": web_acl.get("Id"),
                "description": web_acl.get("Description"),
                "arn": web_acl.get("ARN"),
                "lock_token": web_acl.get("LockToken")
            })

        return {
            "web_acls": web_acls,
            "total_count": len(web_acls),
            "next_marker": response.get("NextMarker")
        }

    async def _get_web_acl(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get details for a specific Web ACL."""
        params = {
            "Name": arguments["name"],
            "Scope": arguments["scope"],
            "Id": arguments["id"]
        }

        response = self.client.get_web_acl(**params)
        
        web_acl = response.get("WebACL", {})
        return {
            "name": web_acl.get("Name"),
            "id": web_acl.get("Id"),
            "arn": web_acl.get("ARN"),
            "default_action": web_acl.get("DefaultAction"),
            "description": web_acl.get("Description"),
            "rules": web_acl.get("Rules", []),
            "visibility_config": web_acl.get("VisibilityConfig"),
            "capacity": web_acl.get("Capacity"),
            "pre_process_firewall_manager_rule_groups": web_acl.get("PreProcessFirewallManagerRuleGroups", []),
            "post_process_firewall_manager_rule_groups": web_acl.get("PostProcessFirewallManagerRuleGroups", []),
            "managed_by_firewall_manager": web_acl.get("ManagedByFirewallManager"),
            "label_namespace": web_acl.get("LabelNamespace"),
            "custom_response_bodies": web_acl.get("CustomResponseBodies", {}),
            "captcha_config": web_acl.get("CaptchaConfig"),
            "challenge_config": web_acl.get("ChallengeConfig"),
            "token_domains": web_acl.get("TokenDomains", []),
            "association_config": web_acl.get("AssociationConfig"),
            "lock_token": response.get("LockToken")
        }

    async def _list_ip_sets(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """List WAF IP sets."""
        params = {
            "Scope": arguments.get("scope", "REGIONAL")
        }
        if "limit" in arguments:
            params["Limit"] = arguments["limit"]

        response = self.client.list_ip_sets(**params)
        
        ip_sets = []
        for ip_set in response.get("IPSets", []):
            ip_sets.append({
                "name": ip_set.get("Name"),
                "id": ip_set.get("Id"),
                "description": ip_set.get("Description"),
                "arn": ip_set.get("ARN"),
                "lock_token": ip_set.get("LockToken")
            })

        return {
            "ip_sets": ip_sets,
            "total_count": len(ip_sets),
            "next_marker": response.get("NextMarker")
        }

    async def _list_rule_groups(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """List WAF rule groups."""
        params = {
            "Scope": arguments.get("scope", "REGIONAL")
        }
        if "limit" in arguments:
            params["Limit"] = arguments["limit"]

        response = self.client.list_rule_groups(**params)
        
        rule_groups = []
        for rule_group in response.get("RuleGroups", []):
            rule_groups.append({
                "name": rule_group.get("Name"),
                "id": rule_group.get("Id"),
                "description": rule_group.get("Description"),
                "arn": rule_group.get("ARN"),
                "lock_token": rule_group.get("LockToken")
            })

        return {
            "rule_groups": rule_groups,
            "total_count": len(rule_groups),
            "next_marker": response.get("NextMarker")
        }