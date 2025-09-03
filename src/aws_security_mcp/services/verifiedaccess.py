"""Verified Access service."""

import mcp.types as types
from .base import BaseAWSService

class VerifiedAccessService(BaseAWSService):
    def __init__(self, session):
        super().__init__(session)
        self.client = self.get_client("ec2")

    def get_tools(self):
        return [
            types.Tool(name="verifiedaccess_describe_instances", description="List instances", inputSchema={"type": "object", "properties": {}}),
            types.Tool(name="verifiedaccess_describe_groups", description="List groups", inputSchema={"type": "object", "properties": {}})
        ]

    async def handle_tool_call(self, name, arguments):
        try:
            if name == "verifiedaccess_describe_instances":
                return {"instances": self.client.describe_verified_access_instances().get("VerifiedAccessInstances", [])}
            elif name == "verifiedaccess_describe_groups":
                return {"groups": self.client.describe_verified_access_groups().get("VerifiedAccessGroups", [])}
        except Exception as e:
            return {"error": str(e)}