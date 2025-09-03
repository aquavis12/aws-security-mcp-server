"""Network Firewall service."""

import mcp.types as types
from .base import BaseAWSService

class NetworkFirewallService(BaseAWSService):
    def __init__(self, session):
        super().__init__(session)
        self.client = self.get_client("network-firewall")

    def get_tools(self):
        return [
            types.Tool(name="networkfirewall_list_firewalls", description="List firewalls", inputSchema={"type": "object", "properties": {}}),
            types.Tool(name="networkfirewall_describe_firewall", description="Describe firewall", inputSchema={"type": "object", "properties": {"firewall_name": {"type": "string"}}, "required": ["firewall_name"]}),
            types.Tool(name="networkfirewall_list_rule_groups", description="List rule groups", inputSchema={"type": "object", "properties": {}})
        ]

    async def handle_tool_call(self, name, arguments):
        try:
            if name == "networkfirewall_list_firewalls":
                return {"firewalls": self.client.list_firewalls().get("Firewalls", [])}
            elif name == "networkfirewall_describe_firewall":
                return {"firewall": self.client.describe_firewall(FirewallName=arguments["firewall_name"])}
            elif name == "networkfirewall_list_rule_groups":
                return {"rule_groups": self.client.list_rule_groups().get("RuleGroups", [])}
        except Exception as e:
            return {"error": str(e)}