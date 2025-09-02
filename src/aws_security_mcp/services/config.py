"""Config service implementation for AWS Security MCP Server."""

import logging
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError
import mcp.types as types

logger = logging.getLogger(__name__)


class ConfigService:
    """Service for handling AWS Config operations."""

    def __init__(self, session: boto3.Session):
        """Initialize the Config service."""
        self.client = session.client("config")

    def get_tools(self) -> List[types.Tool]:
        """Get available Config tools."""
        return [
            types.Tool(
                name="config_describe_config_rules",
                description="List AWS Config rules",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "config_rule_names": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of specific rule names to describe"
                        }
                    }
                }
            ),
            types.Tool(
                name="config_get_compliance_details_by_config_rule",
                description="Get compliance details for a Config rule",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "config_rule_name": {
                            "type": "string",
                            "description": "Name of the Config rule"
                        },
                        "compliance_types": {
                            "type": "array",
                            "items": {
                                "type": "string",
                                "enum": ["COMPLIANT", "NON_COMPLIANT", "NOT_APPLICABLE", "INSUFFICIENT_DATA"]
                            },
                            "description": "Filter by compliance types"
                        },
                        "limit": {
                            "type": "integer",
                            "minimum": 0,
                            "maximum": 100,
                            "default": 50
                        }
                    },
                    "required": ["config_rule_name"]
                }
            ),
            types.Tool(
                name="config_describe_configuration_recorders",
                description="Get AWS Config configuration recorders",
                inputSchema={
                    "type": "object",
                    "properties": {}
                }
            )
        ]

    async def handle_tool_call(self, name: str, arguments: Dict[str, Any]) -> Any:
        """Handle Config tool calls."""
        try:
            if name == "config_describe_config_rules":
                return await self._describe_config_rules(arguments)
            elif name == "config_get_compliance_details_by_config_rule":
                return await self._get_compliance_details_by_config_rule(arguments)
            elif name == "config_describe_configuration_recorders":
                return await self._describe_configuration_recorders(arguments)
            else:
                raise ValueError(f"Unknown Config tool: {name}")

        except ClientError as e:
            logger.error(f"AWS client error in {name}: {e}")
            return {"error": str(e), "service": "config", "operation": name}
        except Exception as e:
            logger.error(f"Unexpected error in {name}: {e}")
            return {"error": str(e), "service": "config", "operation": name}

    async def _describe_config_rules(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Describe Config rules."""
        params = {}
        if "config_rule_names" in arguments:
            params["ConfigRuleNames"] = arguments["config_rule_names"]

        response = self.client.describe_config_rules(**params)
        
        rules = []
        for rule in response.get("ConfigRules", []):
            rules.append({
                "config_rule_name": rule.get("ConfigRuleName"),
                "config_rule_arn": rule.get("ConfigRuleArn"),
                "config_rule_id": rule.get("ConfigRuleId"),
                "description": rule.get("Description"),
                "config_rule_state": rule.get("ConfigRuleState"),
                "source": rule.get("Source", {}),
                "input_parameters": rule.get("InputParameters"),
                "maximum_execution_frequency": rule.get("MaximumExecutionFrequency")
            })

        return {
            "config_rules": rules,
            "total_count": len(rules)
        }

    async def _get_compliance_details_by_config_rule(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get compliance details for a Config rule."""
        params = {
            "ConfigRuleName": arguments["config_rule_name"]
        }
        
        if "compliance_types" in arguments:
            params["ComplianceTypes"] = arguments["compliance_types"]
        if "limit" in arguments:
            params["Limit"] = arguments["limit"]

        response = self.client.get_compliance_details_by_config_rule(**params)
        
        evaluation_results = []
        for result in response.get("EvaluationResults", []):
            evaluation_results.append({
                "evaluation_result_identifier": result.get("EvaluationResultIdentifier"),
                "compliance_type": result.get("ComplianceType"),
                "result_recorded_time": result.get("ResultRecordedTime").isoformat() if result.get("ResultRecordedTime") else None,
                "config_rule_invoked_time": result.get("ConfigRuleInvokedTime").isoformat() if result.get("ConfigRuleInvokedTime") else None,
                "annotation": result.get("Annotation")
            })

        return {
            "evaluation_results": evaluation_results,
            "total_count": len(evaluation_results),
            "next_token": response.get("NextToken")
        }

    async def _describe_configuration_recorders(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Describe configuration recorders."""
        response = self.client.describe_configuration_recorders()
        
        recorders = []
        for recorder in response.get("ConfigurationRecorders", []):
            recorders.append({
                "name": recorder.get("name"),
                "role_arn": recorder.get("roleARN"),
                "recording_group": recorder.get("recordingGroup")
            })

        return {
            "configuration_recorders": recorders,
            "total_count": len(recorders)
        }