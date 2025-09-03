"""Audit Manager service."""

import mcp.types as types
from .base import BaseAWSService

class AuditManagerService(BaseAWSService):
    def __init__(self, session):
        super().__init__(session)
        self.client = self.get_client("auditmanager")

    def get_tools(self):
        return [
            types.Tool(name="auditmanager_list_assessments", description="List assessments", inputSchema={"type": "object", "properties": {}}),
            types.Tool(name="auditmanager_list_frameworks", description="List frameworks", inputSchema={"type": "object", "properties": {}})
        ]

    async def handle_tool_call(self, name, arguments):
        try:
            if name == "auditmanager_list_assessments":
                return {"assessments": self.client.list_assessments().get("assessmentMetadata", [])}
            elif name == "auditmanager_list_frameworks":
                return {"frameworks": self.client.list_assessment_frameworks().get("frameworkMetadataList", [])}
        except Exception as e:
            return {"error": str(e)}