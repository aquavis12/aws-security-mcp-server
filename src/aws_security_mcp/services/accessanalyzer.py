"""Access Analyzer service."""

import mcp.types as types
from .base import BaseAWSService

class AccessAnalyzerService(BaseAWSService):
    def __init__(self, session):
        super().__init__(session)
        self.client = self.get_client("accessanalyzer")

    def get_tools(self):
        return [
            types.Tool(name="accessanalyzer_list_analyzers", description="List Access Analyzers", inputSchema={"type": "object", "properties": {}}),
            types.Tool(name="accessanalyzer_list_findings", description="List findings", inputSchema={"type": "object", "properties": {"analyzer_arn": {"type": "string"}}, "required": ["analyzer_arn"]})
        ]

    async def handle_tool_call(self, name, arguments):
        try:
            if name == "accessanalyzer_list_analyzers":
                return {"analyzers": self.client.list_analyzers().get("analyzers", [])}
            elif name == "accessanalyzer_list_findings":
                return {"findings": self.client.list_findings(analyzerArn=arguments["analyzer_arn"]).get("findings", [])}
        except Exception as e:
            return {"error": str(e)}