"""Config service."""

import mcp.types as types
from .base import BaseAWSService

class ConfigService(BaseAWSService):
    def __init__(self, session):
        super().__init__(session)
        self.client = self.get_client("config")

    def get_tools(self):
        return [
            types.Tool(name="config_describe_config_rules", description="List Config rules", inputSchema={"type": "object", "properties": {}}),
            types.Tool(name="config_get_compliance_details_by_config_rule", description="Get compliance details", inputSchema={"type": "object", "properties": {"config_rule_name": {"type": "string"}}, "required": ["config_rule_name"]}),
            types.Tool(name="config_describe_configuration_recorders", description="Get configuration recorders", inputSchema={"type": "object", "properties": {}})
        ]

    async def handle_tool_call(self, name, arguments):
        try:
            if name == "config_describe_config_rules":
                return {"config_rules": self.client.describe_config_rules().get("ConfigRules", [])}
            elif name == "config_get_compliance_details_by_config_rule":
                return {"compliance": self.client.get_compliance_details_by_config_rule(ConfigRuleName=arguments["config_rule_name"])}
            elif name == "config_describe_configuration_recorders":
                return {"recorders": self.client.describe_configuration_recorders().get("ConfigurationRecorders", [])}
        except Exception as e:
            return {"error": str(e)}