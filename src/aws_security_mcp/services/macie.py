"""Macie service implementation for AWS Security MCP Server."""

import logging
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError
import mcp.types as types

logger = logging.getLogger(__name__)


class MacieService:
    """Service for handling Macie operations."""

    def __init__(self, session: boto3.Session):
        """Initialize the Macie service."""
        self.client = session.client("macie2")

    def get_tools(self) -> List[types.Tool]:
        """Get available Macie tools."""
        return [
            types.Tool(
                name="macie_get_findings",
                description="Get Macie findings",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "finding_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of finding IDs"
                        }
                    },
                    "required": ["finding_ids"]
                }
            ),
            types.Tool(
                name="macie_list_classification_jobs",
                description="List Macie classification jobs",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "filter_criteria": {
                            "type": "object",
                            "description": "Filter criteria for jobs"
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
                name="macie_get_macie_session",
                description="Get Macie session information",
                inputSchema={
                    "type": "object",
                    "properties": {}
                }
            )
        ]

    async def handle_tool_call(self, name: str, arguments: Dict[str, Any]) -> Any:
        """Handle Macie tool calls."""
        try:
            if name == "macie_get_findings":
                return await self._get_findings(arguments)
            elif name == "macie_list_classification_jobs":
                return await self._list_classification_jobs(arguments)
            elif name == "macie_get_macie_session":
                return await self._get_macie_session(arguments)
            else:
                raise ValueError(f"Unknown Macie tool: {name}")

        except ClientError as e:
            logger.error(f"AWS client error in {name}: {e}")
            return {"error": str(e), "service": "macie", "operation": name}
        except Exception as e:
            logger.error(f"Unexpected error in {name}: {e}")
            return {"error": str(e), "service": "macie", "operation": name}

    async def _get_findings(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get Macie findings."""
        finding_ids = arguments["finding_ids"]
        response = self.client.get_findings(findingIds=finding_ids)
        
        findings = []
        for finding in response.get("findings", []):
            findings.append({
                "id": finding.get("id"),
                "account_id": finding.get("accountId"),
                "archived": finding.get("archived"),
                "category": finding.get("category"),
                "classification_details": finding.get("classificationDetails"),
                "count": finding.get("count"),
                "created_at": finding.get("createdAt").isoformat() if finding.get("createdAt") else None,
                "description": finding.get("description"),
                "partition": finding.get("partition"),
                "region": finding.get("region"),
                "resources_affected": finding.get("resourcesAffected"),
                "sample": finding.get("sample"),
                "schema_version": finding.get("schemaVersion"),
                "severity": finding.get("severity"),
                "title": finding.get("title"),
                "type": finding.get("type"),
                "updated_at": finding.get("updatedAt").isoformat() if finding.get("updatedAt") else None
            })

        return {
            "findings": findings,
            "total_count": len(findings)
        }

    async def _list_classification_jobs(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """List Macie classification jobs."""
        params = {}
        if "filter_criteria" in arguments:
            params["filterCriteria"] = arguments["filter_criteria"]
        if "max_results" in arguments:
            params["maxResults"] = arguments["max_results"]

        response = self.client.list_classification_jobs(**params)
        
        jobs = []
        for job in response.get("items", []):
            jobs.append({
                "job_id": job.get("jobId"),
                "job_type": job.get("jobType"),
                "job_status": job.get("jobStatus"),
                "name": job.get("name"),
                "created_at": job.get("createdAt").isoformat() if job.get("createdAt") else None,
                "bucket_definitions": job.get("bucketDefinitions"),
                "user_paused_details": job.get("userPausedDetails")
            })

        return {
            "jobs": jobs,
            "total_count": len(jobs),
            "next_token": response.get("nextToken")
        }

    async def _get_macie_session(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get Macie session information."""
        response = self.client.get_macie_session()
        
        return {
            "created_at": response.get("createdAt").isoformat() if response.get("createdAt") else None,
            "finding_publishing_frequency": response.get("findingPublishingFrequency"),
            "service_role": response.get("serviceRole"),
            "status": response.get("status"),
            "updated_at": response.get("updatedAt").isoformat() if response.get("updatedAt") else None
        }