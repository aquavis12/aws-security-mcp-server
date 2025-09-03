"""VPC Lattice service."""

import mcp.types as types
from .base import BaseAWSService

class VPCLatticeService(BaseAWSService):
    def __init__(self, session):
        super().__init__(session)
        self.client = self.get_client("vpc-lattice")

    def get_tools(self):
        return [
            types.Tool(name="vpclattice_list_services", description="List services", inputSchema={"type": "object", "properties": {}}),
            types.Tool(name="vpclattice_list_service_networks", description="List service networks", inputSchema={"type": "object", "properties": {}}),
            types.Tool(name="vpclattice_get_auth_policy", description="Get auth policy", inputSchema={"type": "object", "properties": {"resource_identifier": {"type": "string"}}, "required": ["resource_identifier"]})
        ]

    async def handle_tool_call(self, name, arguments):
        try:
            if name == "vpclattice_list_services":
                return {"services": self.client.list_services().get("items", [])}
            elif name == "vpclattice_list_service_networks":
                return {"service_networks": self.client.list_service_networks().get("items", [])}
            elif name == "vpclattice_get_auth_policy":
                return {"policy": self.client.get_auth_policy(resourceIdentifier=arguments["resource_identifier"])}
        except Exception as e:
            return {"error": str(e)}