"""Identity Center service."""

import mcp.types as types
from .base import BaseAWSService

class IdentityCenterService(BaseAWSService):
    def __init__(self, session):
        super().__init__(session)
        self.client = self.get_client("sso-admin")

    def get_tools(self):
        return [
            types.Tool(name="identitycenter_list_instances", description="List instances", inputSchema={"type": "object", "properties": {}}),
            types.Tool(name="identitycenter_list_permission_sets", description="List permission sets", inputSchema={"type": "object", "properties": {"instance_arn": {"type": "string"}}, "required": ["instance_arn"]})
        ]

    async def handle_tool_call(self, name, arguments):
        try:
            if name == "identitycenter_list_instances":
                return {"instances": self.client.list_instances().get("Instances", [])}
            elif name == "identitycenter_list_permission_sets":
                return {"permission_sets": self.client.list_permission_sets(InstanceArn=arguments["instance_arn"]).get("PermissionSets", [])}
        except Exception as e:
            return {"error": str(e)}