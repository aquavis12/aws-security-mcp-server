"""Access Analyzer service implementation for AWS Security MCP Server."""

import logging
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError
import mcp.types as types

logger = logging.getLogger(__name__)


class AccessAnalyzerService:
    """Service for handling Access Analyzer operations."""

    def __init__(self, session: boto3.Session):
        """Initialize the Access Analyzer service."""
        self.client = session.client("accessanalyzer")

    def get_tools(self) -> List[types.Tool]:
        """Get available Access Analyzer tools."""
        return [
            types.Tool(
                name="accessanalyzer_list_analyzers",
                description="List Access Analyzers",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "type": {
                            "type": "string",
                            "enum": ["ACCOUNT", "ORGANIZATION"],
                            "description": "Type of analyzer"
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
                name="accessanalyzer_list_findings",
                description="List Access Analyzer findings",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "analyzer_arn": {
                            "type": "string",
                            "description": "ARN of the analyzer"
                        },
                        "max_results": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 100,
                            "default": 50
                        }
                    },
                    "required": ["analyzer_arn"]
                }
            )
        ]

    async def handle_tool_call(self, name: str, arguments: Dict[str, Any]) -> Any:
        """Handle Access Analyzer tool calls."""
        try:
            if name == "accessanalyzer_list_analyzers":
                return await self._list_analyzers(arguments)
            elif name == "accessanalyzer_list_findings":
                return await self._list_findings(arguments)
            else:
                raise ValueError(f"Unknown Access Analyzer tool: {name}")

        except ClientError as e:
            logger.error(f"AWS client error in {name}: {e}")
            return {"error": str(e), "service": "accessanalyzer", "operation": name}
        except Exception as e:
            logger.error(f"Unexpected error in {name}: {e}")
            return {"error": str(e), "service": "accessanalyzer", "operation": name}

    async def _list_analyzers(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """List Access Analyzers."""
        params = {}
        if "type" in arguments:
            params["type"] = arguments["type"]
        if "max_results" in arguments:
            params["maxResults"] = arguments["max_results"]

        response = self.client.list_analyzers(**params)
        
        analyzers = []
        for analyzer in response.get("analyzers", []):
            analyzers.append({
                "arn": analyzer.get("arn"),
                "name": analyzer.get("name"),
                "type": analyzer.get("type"),
                "created_at": analyzer.get("createdAt").isoformat() if analyzer.get("createdAt") else None,
                "last_resource_analyzed": analyzer.get("lastResourceAnalyzed"),
                "last_resource_analyzed_at": analyzer.get("lastResourceAnalyzedAt").isoformat() if analyzer.get("lastResourceAnalyzedAt") else None,
                "status": analyzer.get("status"),
                "tags": analyzer.get("tags", {})
            })

        return {
            "analyzers": analyzers,
            "total_count": len(analyzers),
            "next_token": response.get("nextToken")
        }

    async def _list_findings(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """List Access Analyzer findings."""
        params = {
            "analyzerArn": arguments["analyzer_arn"]
        }
        if "max_results" in arguments:
            params["maxResults"] = arguments["max_results"]

        response = self.client.list_findings(**params)
        
        findings = []
        for finding in response.get("findings", []):
            findings.append({
                "id": finding.get("id"),
                "principal": finding.get("principal"),
                "action": finding.get("action"),
                "resource": finding.get("resource"),
                "resource_type": finding.get("resourceType"),
                "condition": finding.get("condition"),
                "created_at": finding.get("createdAt").isoformat() if finding.get("createdAt") else None,
                "analyzed_at": finding.get("analyzedAt").isoformat() if finding.get("analyzedAt") else None,
                "updated_at": finding.get("updatedAt").isoformat() if finding.get("updatedAt") else None,
                "status": finding.get("status"),
                "resource_owner_account": finding.get("resourceOwnerAccount")
            })

        return {
            "findings": findings,
            "total_count": len(findings),
            "next_token": response.get("nextToken")
        }