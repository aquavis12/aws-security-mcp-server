"""WAF service."""

import mcp.types as types
from .base import BaseAWSService

class WAFService(BaseAWSService):
    def __init__(self, session):
        super().__init__(session)
        self.client = self.get_client("wafv2")

    def get_tools(self):
        return [
            types.Tool(name="waf_list_web_acls", description="List Web ACLs", inputSchema={"type": "object", "properties": {}}),
            types.Tool(name="waf_get_web_acl", description="Get Web ACL details", inputSchema={"type": "object", "properties": {"name": {"type": "string"}, "id": {"type": "string"}}, "required": ["name", "id"]}),
            types.Tool(name="waf_list_ip_sets", description="List IP sets", inputSchema={"type": "object", "properties": {}}),
            types.Tool(name="waf_list_rule_groups", description="List rule groups", inputSchema={"type": "object", "properties": {}})
        ]

    async def handle_tool_call(self, name, arguments):
        try:
            if name == "waf_list_web_acls":
                return {"web_acls": self.client.list_web_acls(Scope="REGIONAL").get("WebACLs", [])}
            elif name == "waf_get_web_acl":
                return {"web_acl": self.client.get_web_acl(Name=arguments["name"], Id=arguments["id"], Scope="REGIONAL")}
            elif name == "waf_list_ip_sets":
                return {"ip_sets": self.client.list_ip_sets(Scope="REGIONAL").get("IPSets", [])}
            elif name == "waf_list_rule_groups":
                return {"rule_groups": self.client.list_rule_groups(Scope="REGIONAL").get("RuleGroups", [])}
        except Exception as e:
            return {"error": str(e)}