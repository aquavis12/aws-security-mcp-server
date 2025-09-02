"""CloudWatch service implementation for AWS Security MCP Server."""

import logging
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError
import mcp.types as types

logger = logging.getLogger(__name__)


class CloudWatchService:
    """Service for handling CloudWatch operations."""

    def __init__(self, session: boto3.Session):
        """Initialize the CloudWatch service."""
        self.client = session.client("cloudwatch")

    def get_tools(self) -> List[types.Tool]:
        """Get available CloudWatch tools."""
        return [
            types.Tool(
                name="cloudwatch_list_metrics",
                description="List CloudWatch metrics",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "namespace": {
                            "type": "string",
                            "description": "Metric namespace to filter by"
                        },
                        "metric_name": {
                            "type": "string",
                            "description": "Metric name to filter by"
                        },
                        "max_records": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 500,
                            "default": 100
                        }
                    }
                }
            ),
            types.Tool(
                name="cloudwatch_list_alarms",
                description="List CloudWatch alarms",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "state_value": {
                            "type": "string",
                            "enum": ["OK", "ALARM", "INSUFFICIENT_DATA"],
                            "description": "Filter by alarm state"
                        },
                        "action_prefix": {
                            "type": "string",
                            "description": "Filter by action prefix"
                        },
                        "max_records": {
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
        """Handle CloudWatch tool calls."""
        try:
            if name == "cloudwatch_list_metrics":
                return await self._list_metrics(arguments)
            elif name == "cloudwatch_list_alarms":
                return await self._list_alarms(arguments)
            else:
                raise ValueError(f"Unknown CloudWatch tool: {name}")

        except ClientError as e:
            logger.error(f"AWS client error in {name}: {e}")
            return {"error": str(e), "service": "cloudwatch", "operation": name}
        except Exception as e:
            logger.error(f"Unexpected error in {name}: {e}")
            return {"error": str(e), "service": "cloudwatch", "operation": name}

    async def _list_metrics(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """List CloudWatch metrics."""
        params = {}
        if "namespace" in arguments:
            params["Namespace"] = arguments["namespace"]
        if "metric_name" in arguments:
            params["MetricName"] = arguments["metric_name"]
        if "max_records" in arguments:
            params["MaxRecords"] = arguments["max_records"]

        response = self.client.list_metrics(**params)
        
        return {
            "metrics": response.get("Metrics", []),
            "next_token": response.get("NextToken")
        }

    async def _list_alarms(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """List CloudWatch alarms."""
        params = {}
        if "state_value" in arguments:
            params["StateValue"] = arguments["state_value"]
        if "action_prefix" in arguments:
            params["ActionPrefix"] = arguments["action_prefix"]
        if "max_records" in arguments:
            params["MaxRecords"] = arguments["max_records"]

        response = self.client.describe_alarms(**params)
        
        return {
            "metric_alarms": response.get("MetricAlarms", []),
            "composite_alarms": response.get("CompositeAlarms", []),
            "next_token": response.get("NextToken")
        }