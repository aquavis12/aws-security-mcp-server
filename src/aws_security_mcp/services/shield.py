"""Shield service."""

import mcp.types as types
from .base import BaseAWSService

class ShieldService(BaseAWSService):
    def __init__(self, session):
        super().__init__(session)
        self.client = self.get_client("shield")

    def get_tools(self):
        return [
            types.Tool(name="shield_list_protections", description="List protections", inputSchema={"type": "object", "properties": {}}),
            types.Tool(name="shield_describe_protection", description="Describe protection", inputSchema={"type": "object", "properties": {"protection_id": {"type": "string"}}, "required": ["protection_id"]}),
            types.Tool(name="shield_get_subscription_state", description="Get subscription state", inputSchema={"type": "object", "properties": {}}),
            types.Tool(name="shield_list_attacks", description="List attacks", inputSchema={"type": "object", "properties": {}})
        ]

    async def handle_tool_call(self, name, arguments):
        try:
            if name == "shield_list_protections":
                return {"protections": self.client.list_protections().get("Protections", [])}
            elif name == "shield_describe_protection":
                return {"protection": self.client.describe_protection(ProtectionId=arguments["protection_id"])}
            elif name == "shield_get_subscription_state":
                return {"subscription": self.client.get_subscription_state()}
            elif name == "shield_list_attacks":
                return {"attacks": self.client.list_attacks().get("AttackSummaries", [])}
        except Exception as e:
            return {"error": str(e)}