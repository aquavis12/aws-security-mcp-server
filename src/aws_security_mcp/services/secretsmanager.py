"""Secrets Manager service."""

import mcp.types as types
from .base import BaseAWSService

class SecretsManagerService(BaseAWSService):
    def __init__(self, session):
        super().__init__(session)
        self.client = self.get_client("secretsmanager")

    def get_tools(self):
        return [
            types.Tool(name="secretsmanager_list_secrets", description="List secrets", inputSchema={"type": "object", "properties": {}}),
            types.Tool(name="secretsmanager_describe_secret", description="Get secret details", inputSchema={"type": "object", "properties": {"secret_id": {"type": "string"}}, "required": ["secret_id"]}),
            types.Tool(name="secretsmanager_get_resource_policy", description="Get resource policy", inputSchema={"type": "object", "properties": {"secret_id": {"type": "string"}}, "required": ["secret_id"]})
        ]

    async def handle_tool_call(self, name, arguments):
        try:
            if name == "secretsmanager_list_secrets":
                return {"secrets": self.client.list_secrets().get("SecretList", [])}
            elif name == "secretsmanager_describe_secret":
                return {"secret": self.client.describe_secret(SecretId=arguments["secret_id"])}
            elif name == "secretsmanager_get_resource_policy":
                return {"policy": self.client.get_resource_policy(SecretId=arguments["secret_id"])}
        except Exception as e:
            return {"error": str(e)}