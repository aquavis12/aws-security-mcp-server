"""Macie service."""

import mcp.types as types
from .base import BaseAWSService

class MacieService(BaseAWSService):
    def __init__(self, session):
        super().__init__(session)
        self.client = self.get_client("macie2")

    def get_tools(self):
        return [
            types.Tool(name="macie_get_findings", description="Get Macie findings", inputSchema={"type": "object", "properties": {}}),
            types.Tool(name="macie_list_classification_jobs", description="List classification jobs", inputSchema={"type": "object", "properties": {}}),
            types.Tool(name="macie_get_macie_session", description="Get session info", inputSchema={"type": "object", "properties": {}})
        ]

    async def handle_tool_call(self, name, arguments):
        try:
            if name == "macie_get_findings":
                return {"findings": self.client.list_findings().get("findingIds", [])}
            elif name == "macie_list_classification_jobs":
                return {"jobs": self.client.list_classification_jobs().get("items", [])}
            elif name == "macie_get_macie_session":
                return {"session": self.client.get_macie_session()}
        except Exception as e:
            return {"error": str(e)}