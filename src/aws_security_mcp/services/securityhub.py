"""Security Hub service."""

import mcp.types as types
from .base import BaseAWSService

class SecurityHubService(BaseAWSService):
    def __init__(self, session):
        super().__init__(session)
        self.client = self.get_client("securityhub")

    def get_tools(self):
        return [
            types.Tool(name="securityhub_get_findings", description="Get Security Hub findings", inputSchema={"type": "object", "properties": {}}),
            types.Tool(name="securityhub_get_enabled_standards", description="Get enabled standards", inputSchema={"type": "object", "properties": {}}),
            types.Tool(name="securityhub_describe_hub", description="Get hub configuration", inputSchema={"type": "object", "properties": {}})
        ]

    async def handle_tool_call(self, name, arguments):
        try:
            if name == "securityhub_get_findings":
                return {"findings": self.client.get_findings().get("Findings", [])}
            elif name == "securityhub_get_enabled_standards":
                return {"standards": self.client.get_enabled_standards().get("StandardsSubscriptions", [])}
            elif name == "securityhub_describe_hub":
                return {"hub": self.client.describe_hub()}
        except Exception as e:
            return {"error": str(e)}