"""KMS service."""

import mcp.types as types
from .base import BaseAWSService

class KMSService(BaseAWSService):
    def __init__(self, session):
        super().__init__(session)
        self.client = self.get_client("kms")

    def get_tools(self):
        return [
            types.Tool(name="kms_list_keys", description="List KMS keys", inputSchema={"type": "object", "properties": {}}),
            types.Tool(name="kms_describe_key", description="Get key details", inputSchema={"type": "object", "properties": {"key_id": {"type": "string"}}, "required": ["key_id"]}),
            types.Tool(name="kms_get_key_rotation_status", description="Get key rotation status", inputSchema={"type": "object", "properties": {"key_id": {"type": "string"}}, "required": ["key_id"]}),
            types.Tool(name="kms_list_aliases", description="List KMS key aliases", inputSchema={"type": "object", "properties": {}}),
            types.Tool(name="kms_audit_key_usage", description="Audit KMS key usage", inputSchema={"type": "object", "properties": {}})
        ]

    async def handle_tool_call(self, name, arguments):
        try:
            if name == "kms_list_keys":
                return {"keys": self.client.list_keys().get("Keys", [])}
            elif name == "kms_describe_key":
                return {"key": self.client.describe_key(KeyId=arguments["key_id"])["KeyMetadata"]}
            elif name == "kms_get_key_rotation_status":
                return {"rotation_enabled": self.client.get_key_rotation_status(KeyId=arguments["key_id"])["KeyRotationEnabled"]}
            elif name == "kms_list_aliases":
                return {"aliases": self.client.list_aliases().get("Aliases", [])}
            elif name == "kms_audit_key_usage":
                keys = self.client.list_keys().get("Keys", [])
                return {"total_keys": len(keys), "keys": keys[:10]}
        except Exception as e:
            return {"error": str(e)}