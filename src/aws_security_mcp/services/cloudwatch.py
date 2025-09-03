"""CloudWatch service."""

import mcp.types as types
from .base import BaseAWSService

class CloudWatchService(BaseAWSService):
    def __init__(self, session):
        super().__init__(session)
        self.client = self.get_client("cloudwatch")

    def get_tools(self):
        return [
            types.Tool(name="cloudwatch_list_metrics", description="List metrics", inputSchema={"type": "object", "properties": {}}),
            types.Tool(name="cloudwatch_list_alarms", description="List alarms", inputSchema={"type": "object", "properties": {}})
        ]

    async def handle_tool_call(self, name, arguments):
        try:
            if name == "cloudwatch_list_metrics":
                return {"metrics": self.client.list_metrics().get("Metrics", [])}
            elif name == "cloudwatch_list_alarms":
                return {"alarms": self.client.describe_alarms().get("MetricAlarms", [])}
        except Exception as e:
            return {"error": str(e)}