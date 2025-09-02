"""Security Hub service implementation for AWS Security MCP Server."""

import logging
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError
import mcp.types as types

logger = logging.getLogger(__name__)


class SecurityHubService:
    """Service for handling Security Hub operations."""

    def __init__(self, session: boto3.Session):
        """Initialize the Security Hub service."""
        self.client = session.client("securityhub")

    def get_tools(self) -> List[types.Tool]:
        """Get available Security Hub tools."""
        return [
            types.Tool(
                name="securityhub_get_findings",
                description="Get Security Hub findings",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "max_results": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 100,
                            "default": 50
                        },
                        "filters": {
                            "type": "object",
                            "description": "Filters to apply to findings"
                        }
                    }
                }
            ),
            types.Tool(
                name="securityhub_get_enabled_standards",
                description="Get enabled Security Hub standards",
                inputSchema={
                    "type": "object",
                    "properties": {
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
                name="securityhub_describe_hub",
                description="Get Security Hub configuration",
                inputSchema={
                    "type": "object",
                    "properties": {}
                }
            )
        ]

    async def handle_tool_call(self, name: str, arguments: Dict[str, Any]) -> Any:
        """Handle Security Hub tool calls."""
        try:
            if name == "securityhub_get_findings":
                return await self._get_findings(arguments)
            elif name == "securityhub_get_enabled_standards":
                return await self._get_enabled_standards(arguments)
            elif name == "securityhub_describe_hub":
                return await self._describe_hub(arguments)
            else:
                raise ValueError(f"Unknown Security Hub tool: {name}")

        except ClientError as e:
            logger.error(f"AWS client error in {name}: {e}")
            return {"error": str(e), "service": "securityhub", "operation": name}
        except Exception as e:
            logger.error(f"Unexpected error in {name}: {e}")
            return {"error": str(e), "service": "securityhub", "operation": name}

    async def _get_findings(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get Security Hub findings."""
        params = {}
        if "max_results" in arguments:
            params["MaxResults"] = arguments["max_results"]
        if "filters" in arguments:
            params["Filters"] = arguments["filters"]

        response = self.client.get_findings(**params)
        
        findings = []
        for finding in response.get("Findings", []):
            findings.append({
                "id": finding.get("Id"),
                "product_arn": finding.get("ProductArn"),
                "generator_id": finding.get("GeneratorId"),
                "aws_account_id": finding.get("AwsAccountId"),
                "title": finding.get("Title"),
                "description": finding.get("Description"),
                "severity": finding.get("Severity", {}).get("Label"),
                "compliance": finding.get("Compliance", {}).get("Status"),
                "workflow_state": finding.get("WorkflowState"),
                "record_state": finding.get("RecordState"),
                "created_at": finding.get("CreatedAt"),
                "updated_at": finding.get("UpdatedAt")
            })

        return {
            "findings": findings,
            "total_count": len(findings),
            "next_token": response.get("NextToken")
        }

    async def _get_enabled_standards(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get enabled Security Hub standards."""
        params = {}
        if "max_results" in arguments:
            params["MaxResults"] = arguments["max_results"]

        response = self.client.get_enabled_standards(**params)
        
        standards = []
        for standard in response.get("StandardsSubscriptions", []):
            standards.append({
                "standards_subscription_arn": standard.get("StandardsSubscriptionArn"),
                "standards_arn": standard.get("StandardsArn"),
                "standards_input": standard.get("StandardsInput"),
                "standards_status": standard.get("StandardsStatus")
            })

        return {
            "standards": standards,
            "total_count": len(standards),
            "next_token": response.get("NextToken")
        }

    async def _describe_hub(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Describe Security Hub configuration."""
        response = self.client.describe_hub()
        
        return {
            "hub_arn": response.get("HubArn"),
            "subscribed_at": response.get("SubscribedAt"),
            "auto_enable_controls": response.get("AutoEnableControls"),
            "control_finding_generator": response.get("ControlFindingGenerator")
        }