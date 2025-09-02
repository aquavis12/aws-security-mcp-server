"""Network Firewall service implementation for AWS Security MCP Server."""

import logging
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError
import mcp.types as types

logger = logging.getLogger(__name__)


class NetworkFirewallService:
    """Service for handling Network Firewall operations."""

    def __init__(self, session: boto3.Session):
        """Initialize the Network Firewall service."""
        self.client = session.client("network-firewall")

    def get_tools(self) -> List[types.Tool]:
        """Get available Network Firewall tools."""
        return [
            types.Tool(
                name="networkfirewall_list_firewalls",
                description="List Network Firewalls",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "vpc_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of VPC IDs to filter by"
                        },
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
                name="networkfirewall_describe_firewall",
                description="Describe a specific Network Firewall",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "firewall_name": {
                            "type": "string",
                            "description": "Name of the firewall"
                        },
                        "firewall_arn": {
                            "type": "string",
                            "description": "ARN of the firewall"
                        }
                    }
                }
            ),
            types.Tool(
                name="networkfirewall_list_rule_groups",
                description="List Network Firewall rule groups",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "scope": {
                            "type": "string",
                            "enum": ["MANAGED", "ACCOUNT"],
                            "description": "Scope of rule groups"
                        },
                        "managed_type": {
                            "type": "string",
                            "enum": ["AWS_MANAGED_THREAT_SIGNATURES", "AWS_MANAGED_DOMAIN_LISTS"],
                            "description": "Type of managed rule groups"
                        },
                        "type": {
                            "type": "string",
                            "enum": ["STATELESS", "STATEFUL"],
                            "description": "Type of rule groups"
                        },
                        "max_results": {
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
        """Handle Network Firewall tool calls."""
        try:
            if name == "networkfirewall_list_firewalls":
                return await self._list_firewalls(arguments)
            elif name == "networkfirewall_describe_firewall":
                return await self._describe_firewall(arguments)
            elif name == "networkfirewall_list_rule_groups":
                return await self._list_rule_groups(arguments)
            else:
                raise ValueError(f"Unknown Network Firewall tool: {name}")

        except ClientError as e:
            logger.error(f"AWS client error in {name}: {e}")
            return {"error": str(e), "service": "networkfirewall", "operation": name}
        except Exception as e:
            logger.error(f"Unexpected error in {name}: {e}")
            return {"error": str(e), "service": "networkfirewall", "operation": name}

    async def _list_firewalls(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """List Network Firewalls."""
        params = {}
        if "vpc_ids" in arguments:
            params["VpcIds"] = arguments["vpc_ids"]
        if "max_results" in arguments:
            params["MaxResults"] = arguments["max_results"]

        response = self.client.list_firewalls(**params)
        
        firewalls = []
        for firewall in response.get("Firewalls", []):
            firewalls.append({
                "firewall_name": firewall.get("FirewallName"),
                "firewall_arn": firewall.get("FirewallArn")
            })

        return {
            "firewalls": firewalls,
            "total_count": len(firewalls),
            "next_token": response.get("NextToken")
        }

    async def _describe_firewall(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Describe a Network Firewall."""
        params = {}
        if "firewall_name" in arguments:
            params["FirewallName"] = arguments["firewall_name"]
        elif "firewall_arn" in arguments:
            params["FirewallArn"] = arguments["firewall_arn"]
        else:
            raise ValueError("Either firewall_name or firewall_arn must be provided")

        response = self.client.describe_firewall(**params)
        
        firewall = response.get("Firewall", {})
        firewall_status = response.get("FirewallStatus", {})
        
        return {
            "firewall_name": firewall.get("FirewallName"),
            "firewall_arn": firewall.get("FirewallArn"),
            "firewall_policy_arn": firewall.get("FirewallPolicyArn"),
            "vpc_id": firewall.get("VpcId"),
            "subnet_mappings": firewall.get("SubnetMappings", []),
            "delete_protection": firewall.get("DeleteProtection"),
            "subnet_change_protection": firewall.get("SubnetChangeProtection"),
            "firewall_policy_change_protection": firewall.get("FirewallPolicyChangeProtection"),
            "description": firewall.get("Description"),
            "firewall_id": firewall.get("FirewallId"),
            "tags": firewall.get("Tags", []),
            "encryption_configuration": firewall.get("EncryptionConfiguration"),
            "status": firewall_status.get("Status"),
            "configuration_sync_state_summary": firewall_status.get("ConfigurationSyncStateSummary"),
            "sync_states": firewall_status.get("SyncStates", {}),
            "capacity_usage_summary": firewall_status.get("CapacityUsageSummary")
        }

    async def _list_rule_groups(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """List Network Firewall rule groups."""
        params = {}
        if "scope" in arguments:
            params["Scope"] = arguments["scope"]
        if "managed_type" in arguments:
            params["ManagedType"] = arguments["managed_type"]
        if "type" in arguments:
            params["Type"] = arguments["type"]
        if "max_results" in arguments:
            params["MaxResults"] = arguments["max_results"]

        response = self.client.list_rule_groups(**params)
        
        rule_groups = []
        for rule_group in response.get("RuleGroups", []):
            rule_groups.append({
                "name": rule_group.get("Name"),
                "arn": rule_group.get("Arn")
            })

        return {
            "rule_groups": rule_groups,
            "total_count": len(rule_groups),
            "next_token": response.get("NextToken")
        }