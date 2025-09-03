"""GuardDuty service implementation for AWS Security MCP Server."""

import logging
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError
import mcp.types as types

logger = logging.getLogger(__name__)


class GuardDutyService:
    """Service for handling GuardDuty operations."""

    def __init__(self, session: boto3.Session):
        """Initialize the GuardDuty service."""
        self.client = session.client("guardduty")

    def get_tools(self) -> List[types.Tool]:
        """Get available GuardDuty tools."""
        return [
            types.Tool(
                name="guardduty_list_detectors",
                description="List GuardDuty detectors",
                inputSchema={"type": "object", "properties": {}}
            ),
            types.Tool(
                name="guardduty_list_findings",
                description="List GuardDuty findings for a detector",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "detector_id": {"type": "string", "description": "The ID of the detector"}
                    },
                    "required": ["detector_id"]
                }
            ),
            types.Tool(
                name="guardduty_get_detector",
                description="Get GuardDuty detector details",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "detector_id": {"type": "string", "description": "The ID of the detector"}
                    },
                    "required": ["detector_id"]
                }
            )
        ]

    async def handle_tool_call(self, name: str, arguments: Dict[str, Any]) -> Any:
        """Handle GuardDuty tool calls."""
        try:
            if name == "guardduty_list_detectors":
                return await self._list_detectors()
            elif name == "guardduty_list_findings":
                return await self._list_findings(arguments["detector_id"])
            elif name == "guardduty_get_detector":
                return await self._get_detector(arguments["detector_id"])
            else:
                raise ValueError(f"Unknown GuardDuty tool: {name}")
        except ClientError as e:
            return {"error": str(e), "service": "guardduty"}
        except Exception as e:
            return {"error": str(e), "service": "guardduty"}

    async def _list_detectors(self) -> Dict[str, Any]:
        """List GuardDuty detectors."""
        response = self.client.list_detectors()
        return {"detector_ids": response.get("DetectorIds", [])}

    async def _list_findings(self, detector_id: str) -> Dict[str, Any]:
        """List GuardDuty findings."""
        response = self.client.list_findings(DetectorId=detector_id)
        return {"finding_ids": response.get("FindingIds", [])}

    async def _get_detector(self, detector_id: str) -> Dict[str, Any]:
        """Get GuardDuty detector details."""
        response = self.client.get_detector(DetectorId=detector_id)
        return {
            "detector_id": detector_id,
            "status": response.get("Status"),
            "service_role": response.get("ServiceRole"),
            "finding_publishing_frequency": response.get("FindingPublishingFrequency")
        }