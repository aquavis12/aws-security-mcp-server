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
                inputSchema={
                    "type": "object",
                    "properties": {
                        "max_results": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 50,
                            "default": 50
                        }
                    }
                }
            ),
            types.Tool(
                name="guardduty_list_findings",
                description="List GuardDuty findings for a detector",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "detector_id": {
                            "type": "string",
                            "description": "The ID of the detector"
                        },
                        "max_results": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 50,
                            "default": 50
                        }
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
                        "detector_id": {
                            "type": "string",
                            "description": "The ID of the detector"
                        }
                    },
                    "required": ["detector_id"]
                }
            )
        ]

    async def handle_tool_call(self, name: str, arguments: Dict[str, Any]) -> Any:
        """Handle GuardDuty tool calls."""
        try:
            if name == "guardduty_list_detectors":
                return await self._list_detectors(arguments)
            elif name == "guardduty_list_findings":
                return await self._list_findings(arguments)
            elif name == "guardduty_get_detector":
                return await self._get_detector(arguments)
            else:
                raise ValueError(f"Unknown GuardDuty tool: {name}")

        except ClientError as e:
            logger.error(f"AWS client error in {name}: {e}")
            return {"error": str(e), "service": "guardduty", "operation": name}
        except Exception as e:
            logger.error(f"Unexpected error in {name}: {e}")
            return {"error": str(e), "service": "guardduty", "operation": name}

    async def _list_detectors(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """List GuardDuty detectors."""
        params = {}
        if "max_results" in arguments:
            params["MaxResults"] = arguments["max_results"]

        response = self.client.list_detectors(**params)
        return {
            "detector_ids": response.get("DetectorIds", []),
            "total_count": len(response.get("DetectorIds", [])),
            "next_token": response.get("NextToken")
        }

    async def _list_findings(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """List GuardDuty findings for a detector."""
        detector_id = arguments["detector_id"]
        params = {"DetectorId": detector_id}
        
        if "max_results" in arguments:
            params["MaxResults"] = arguments["max_results"]

        response = self.client.list_findings(**params)
        finding_ids = response.get("FindingIds", [])
        
        if finding_ids:
            # Get detailed findings
            findings_response = self.client.get_findings(
                DetectorId=detector_id,
                FindingIds=finding_ids
            )
            findings = []
            for finding in findings_response.get("Findings", []):
                findings.append({
                    "id": finding.get("Id"),
                    "type": finding.get("Type"),
                    "severity": finding.get("Severity"),
                    "title": finding.get("Title"),
                    "description": finding.get("Description"),
                    "created_at": finding.get("CreatedAt"),
                    "updated_at": finding.get("UpdatedAt"),
                    "confidence": finding.get("Confidence"),
                    "region": finding.get("Region")
                })
            return {"findings": findings, "total_count": len(findings)}
        
        return {"findings": [], "total_count": 0}

    async def _get_detector(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get GuardDuty detector details."""
        detector_id = arguments["detector_id"]
        response = self.client.get_detector(DetectorId=detector_id)
        
        return {
            "detector_id": detector_id,
            "status": response.get("Status"),
            "service_role": response.get("ServiceRole"),
            "finding_publishing_frequency": response.get("FindingPublishingFrequency"),
            "created_at": response.get("CreatedAt"),
            "updated_at": response.get("UpdatedAt"),
            "tags": response.get("Tags", {})
        }

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
                inputSchema={
                    "type": "object",
                    "properties": {
                        "max_results": {"type": "integer", "minimum": 1, "maximum": 50, "default": 50},
                        "next_token": {"type": "string"}
                    }
                }
            ),
            types.Tool(
                name="guardduty_get_findings",
                description="Get GuardDuty findings",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "detector_id": {"type": "string", "description": "The ID of the detector"},
                        "finding_ids": {"type": "array", "items": {"type": "string"}}
                    },
                    "required": ["detector_id", "finding_ids"]
                }
            )
        ]

    async def handle_tool_call(self, name: str, arguments: Dict[str, Any]) -> Any:
        """Handle GuardDuty tool calls."""
        try:
            if name == "guardduty_list_detectors":
                return await self._list_detectors(arguments)
            elif name == "guardduty_get_findings":
                return await self._get_findings(arguments)
            else:
                raise ValueError(f"Unknown GuardDuty tool: {name}")

        except ClientError as e:
            logger.error(f"AWS client error in {name}: {e}")
            return {"error": str(e), "service": "guardduty", "operation": name}
        except Exception as e:
            logger.error(f"Unexpected error in {name}: {e}")
            return {"error": str(e), "service": "guardduty", "operation": name}

    async def _list_detectors(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """List GuardDuty detectors."""
        params = {}
        if "max_results" in arguments:
            params["MaxResults"] = arguments["max_results"]
        if "next_token" in arguments:
            params["NextToken"] = arguments["next_token"]

        response = self.client.list_detectors(**params)
        return {"detector_ids": response.get("DetectorIds", []), "next_token": response.get("NextToken")}

    async def _get_findings(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get GuardDuty findings."""
        response = self.client.get_findings(
            DetectorId=arguments["detector_id"],
            FindingIds=arguments["finding_ids"]
        )
        return {"findings": response.get("Findings", [])}
