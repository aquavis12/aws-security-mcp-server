"""Inspector service."""

import mcp.types as types
from .base import BaseAWSService

class InspectorService(BaseAWSService):
    def __init__(self, session):
        super().__init__(session)
        self.client = self.get_client("inspector2")

    def get_tools(self):
        return [
            types.Tool(name="inspector_list_findings", description="List Inspector findings", inputSchema={"type": "object", "properties": {}}),
            types.Tool(name="inspector_get_coverage", description="Get coverage statistics", inputSchema={"type": "object", "properties": {}})
        ]

    async def handle_tool_call(self, name, arguments):
        try:
            if name == "inspector_list_findings":
                return {"findings": self.client.list_findings().get("findings", [])}
            elif name == "inspector_get_coverage":
                return {"coverage": self.client.list_coverage().get("coveredResources", [])}
        except Exception as e:
            return {"error": str(e)}