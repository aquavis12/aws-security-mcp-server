"""CloudTrail service."""

import mcp.types as types
from .base import BaseAWSService

class CloudTrailService(BaseAWSService):
    def __init__(self, session):
        super().__init__(session)
        self.client = self.get_client("cloudtrail")

    def get_tools(self):
        return [
            types.Tool(name="cloudtrail_describe_trails", description="List CloudTrail trails", inputSchema={"type": "object", "properties": {}}),
            types.Tool(name="cloudtrail_get_trail_status", description="Get trail status", inputSchema={"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}),
            types.Tool(name="cloudtrail_lookup_events", description="Look up events", inputSchema={"type": "object", "properties": {}})
        ]

    async def handle_tool_call(self, name, arguments):
        try:
            if name == "cloudtrail_describe_trails":
                return {"trails": self.client.describe_trails().get("trailList", [])}
            elif name == "cloudtrail_get_trail_status":
                return {"status": self.client.get_trail_status(Name=arguments["name"])}
            elif name == "cloudtrail_lookup_events":
                return {"events": self.client.lookup_events().get("Events", [])}
        except Exception as e:
            return {"error": str(e)}