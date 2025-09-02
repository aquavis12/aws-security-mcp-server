"""Inspector service implementation for AWS Security MCP Server."""

import logging
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError
import mcp.types as types

logger = logging.getLogger(__name__)


class InspectorService:
    """Service for handling Inspector operations."""

    def __init__(self, session: boto3.Session):
        """Initialize the Inspector service."""
        self.client = session.client("inspector2")

    def get_tools(self) -> List[types.Tool]:
        """Get available Inspector tools."""
        return [
            types.Tool(
                name="inspector_list_findings",
                description="List Inspector findings",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "filter_criteria": {
                            "type": "object",
                            "description": "Filter criteria for findings"
                        },
                        "max_results": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 100,
                            "default": 50
                        }
                    }
                }
            ),
            types.Tool(
                name="inspector_get_coverage",
                description="Get Inspector coverage statistics",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "filter_criteria": {
                            "type": "object",
                            "description": "Filter criteria for coverage"
                        },
                        "max_results": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 100,
                            "default": 50
                        }
                    }
                }
            )
        ]

    async def handle_tool_call(self, name: str, arguments: Dict[str, Any]) -> Any:
        """Handle Inspector tool calls."""
        try:
            if name == "inspector_list_findings":
                return await self._list_findings(arguments)
            elif name == "inspector_get_coverage":
                return await self._get_coverage(arguments)
            else:
                raise ValueError(f"Unknown Inspector tool: {name}")

        except ClientError as e:
            logger.error(f"AWS client error in {name}: {e}")
            return {"error": str(e), "service": "inspector", "operation": name}
        except Exception as e:
            logger.error(f"Unexpected error in {name}: {e}")
            return {"error": str(e), "service": "inspector", "operation": name}

    async def _list_findings(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """List Inspector findings."""
        params = {}
        if "filter_criteria" in arguments:
            params["filterCriteria"] = arguments["filter_criteria"]
        if "max_results" in arguments:
            params["maxResults"] = arguments["max_results"]

        response = self.client.list_findings(**params)
        
        findings = []
        for finding in response.get("findings", []):
            findings.append({
                "finding_arn": finding.get("findingArn"),
                "aws_account_id": finding.get("awsAccountId"),
                "type": finding.get("type"),
                "description": finding.get("description"),
                "title": finding.get("title"),
                "severity": finding.get("severity"),
                "first_observed_at": finding.get("firstObservedAt").isoformat() if finding.get("firstObservedAt") else None,
                "last_observed_at": finding.get("lastObservedAt").isoformat() if finding.get("lastObservedAt") else None,
                "updated_at": finding.get("updatedAt").isoformat() if finding.get("updatedAt") else None,
                "status": finding.get("status"),
                "resources": finding.get("resources", [])
            })

        return {
            "findings": findings,
            "total_count": len(findings),
            "next_token": response.get("nextToken")
        }

    async def _get_coverage(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get Inspector coverage statistics."""
        params = {}
        if "filter_criteria" in arguments:
            params["filterCriteria"] = arguments["filter_criteria"]
        if "max_results" in arguments:
            params["maxResults"] = arguments["max_results"]

        response = self.client.list_coverage(**params)
        
        covered_resources = []
        for resource in response.get("coveredResources", []):
            covered_resources.append({
                "resource_id": resource.get("resourceId"),
                "resource_type": resource.get("resourceType"),
                "scan_type": resource.get("scanType"),
                "account_id": resource.get("accountId"),
                "resource_metadata": resource.get("resourceMetadata"),
                "scan_status": resource.get("scanStatus")
            })

        return {
            "covered_resources": covered_resources,
            "total_count": len(covered_resources),
            "next_token": response.get("nextToken")
        }