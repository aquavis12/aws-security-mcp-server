"""GuardDuty service."""

import mcp.types as types
from .base import BaseAWSService

class GuardDutyService(BaseAWSService):
    def __init__(self, session):
        super().__init__(session)
        self.client = self.get_client("guardduty")

    def get_tools(self):
        return [
            types.Tool(name="guardduty_list_detectors", description="List GuardDuty detectors", inputSchema={"type": "object", "properties": {}}),
            types.Tool(name="guardduty_list_findings", description="List GuardDuty findings", inputSchema={"type": "object", "properties": {"detector_id": {"type": "string"}}, "required": ["detector_id"]}),
            types.Tool(name="guardduty_get_detector", description="Get detector details", inputSchema={"type": "object", "properties": {"detector_id": {"type": "string"}}, "required": ["detector_id"]})
        ]

    async def handle_tool_call(self, name, arguments):
        try:
            if name == "guardduty_list_detectors":
                return {"detector_ids": self.client.list_detectors().get("DetectorIds", [])}
            elif name == "guardduty_list_findings":
                return {"finding_ids": self.client.list_findings(DetectorId=arguments["detector_id"]).get("FindingIds", [])}
            elif name == "guardduty_get_detector":
                return {"detector": self.client.get_detector(DetectorId=arguments["detector_id"])}
        except Exception as e:
            return {"error": str(e)}