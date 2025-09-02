"""CloudTrail service implementation for AWS Security MCP Server."""

import logging
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError
import mcp.types as types

logger = logging.getLogger(__name__)


class CloudTrailService:
    """Service for handling CloudTrail operations."""

    def __init__(self, session: boto3.Session):
        """Initialize the CloudTrail service."""
        self.client = session.client("cloudtrail")

    def get_tools(self) -> List[types.Tool]:
        """Get available CloudTrail tools."""
        return [
            types.Tool(
                name="cloudtrail_describe_trails",
                description="List CloudTrail trails",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "trail_name_list": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of specific trail names"
                        },
                        "include_shadow_trails": {
                            "type": "boolean",
                            "description": "Include shadow trails",
                            "default": False
                        }
                    }
                }
            ),
            types.Tool(
                name="cloudtrail_get_trail_status",
                description="Get CloudTrail trail status",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string",
                            "description": "Name or ARN of the trail"
                        }
                    },
                    "required": ["name"]
                }
            ),
            types.Tool(
                name="cloudtrail_lookup_events",
                description="Look up CloudTrail events",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "lookup_attributes": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "attribute_key": {
                                        "type": "string",
                                        "enum": ["EventId", "EventName", "ReadOnly", "Username", "ResourceType", "ResourceName", "EventSource", "AccessKeyId"]
                                    },
                                    "attribute_value": {"type": "string"}
                                }
                            }
                        },
                        "start_time": {
                            "type": "string",
                            "description": "Start time for event lookup (ISO format)"
                        },
                        "end_time": {
                            "type": "string",
                            "description": "End time for event lookup (ISO format)"
                        },
                        "max_items": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 50,
                            "default": 50
                        }
                    }
                }
            )
        ]

    async def handle_tool_call(self, name: str, arguments: Dict[str, Any]) -> Any:
        """Handle CloudTrail tool calls."""
        try:
            if name == "cloudtrail_describe_trails":
                return await self._describe_trails(arguments)
            elif name == "cloudtrail_get_trail_status":
                return await self._get_trail_status(arguments)
            elif name == "cloudtrail_lookup_events":
                return await self._lookup_events(arguments)
            else:
                raise ValueError(f"Unknown CloudTrail tool: {name}")

        except ClientError as e:
            logger.error(f"AWS client error in {name}: {e}")
            return {"error": str(e), "service": "cloudtrail", "operation": name}
        except Exception as e:
            logger.error(f"Unexpected error in {name}: {e}")
            return {"error": str(e), "service": "cloudtrail", "operation": name}

    async def _describe_trails(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Describe CloudTrail trails."""
        params = {}
        if "trail_name_list" in arguments:
            params["trailNameList"] = arguments["trail_name_list"]
        if "include_shadow_trails" in arguments:
            params["includeShadowTrails"] = arguments["include_shadow_trails"]

        response = self.client.describe_trails(**params)
        
        trails = []
        for trail in response.get("trailList", []):
            trails.append({
                "name": trail.get("Name"),
                "s3_bucket_name": trail.get("S3BucketName"),
                "s3_key_prefix": trail.get("S3KeyPrefix"),
                "sns_topic_name": trail.get("SnsTopicName"),
                "include_global_service_events": trail.get("IncludeGlobalServiceEvents"),
                "is_multi_region_trail": trail.get("IsMultiRegionTrail"),
                "home_region": trail.get("HomeRegion"),
                "trail_arn": trail.get("TrailARN"),
                "log_file_validation_enabled": trail.get("LogFileValidationEnabled"),
                "cloud_watch_logs_log_group_arn": trail.get("CloudWatchLogsLogGroupArn"),
                "cloud_watch_logs_role_arn": trail.get("CloudWatchLogsRoleArn"),
                "kms_key_id": trail.get("KMSKeyId"),
                "has_custom_event_selectors": trail.get("HasCustomEventSelectors"),
                "has_insight_selectors": trail.get("HasInsightSelectors"),
                "is_organization_trail": trail.get("IsOrganizationTrail")
            })

        return {
            "trails": trails,
            "total_count": len(trails)
        }

    async def _get_trail_status(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get CloudTrail trail status."""
        name = arguments["name"]
        response = self.client.get_trail_status(Name=name)
        
        return {
            "trail_name": name,
            "is_logging": response.get("IsLogging"),
            "latest_delivery_error": response.get("LatestDeliveryError"),
            "latest_notification_error": response.get("LatestNotificationError"),
            "latest_delivery_time": response.get("LatestDeliveryTime").isoformat() if response.get("LatestDeliveryTime") else None,
            "latest_notification_time": response.get("LatestNotificationTime").isoformat() if response.get("LatestNotificationTime") else None,
            "start_logging_time": response.get("StartLoggingTime").isoformat() if response.get("StartLoggingTime") else None,
            "stop_logging_time": response.get("StopLoggingTime").isoformat() if response.get("StopLoggingTime") else None,
            "latest_cloud_watch_logs_delivery_error": response.get("LatestCloudWatchLogsDeliveryError"),
            "latest_cloud_watch_logs_delivery_time": response.get("LatestCloudWatchLogsDeliveryTime").isoformat() if response.get("LatestCloudWatchLogsDeliveryTime") else None,
            "latest_digest_delivery_time": response.get("LatestDigestDeliveryTime").isoformat() if response.get("LatestDigestDeliveryTime") else None,
            "latest_digest_delivery_error": response.get("LatestDigestDeliveryError"),
            "latest_delivery_attempt_time": response.get("LatestDeliveryAttemptTime"),
            "latest_notification_attempt_time": response.get("LatestNotificationAttemptTime"),
            "latest_notification_attempt_succeeded": response.get("LatestNotificationAttemptSucceeded"),
            "latest_delivery_attempt_succeeded": response.get("LatestDeliveryAttemptSucceeded"),
            "time_logging_started": response.get("TimeLoggingStarted"),
            "time_logging_stopped": response.get("TimeLoggingStopped")
        }

    async def _lookup_events(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Look up CloudTrail events."""
        from datetime import datetime
        
        params = {}
        if "lookup_attributes" in arguments:
            params["LookupAttributes"] = [
                {
                    "AttributeKey": attr["attribute_key"],
                    "AttributeValue": attr["attribute_value"]
                }
                for attr in arguments["lookup_attributes"]
            ]
        if "start_time" in arguments:
            params["StartTime"] = datetime.fromisoformat(arguments["start_time"].replace('Z', '+00:00'))
        if "end_time" in arguments:
            params["EndTime"] = datetime.fromisoformat(arguments["end_time"].replace('Z', '+00:00'))
        if "max_items" in arguments:
            params["MaxItems"] = arguments["max_items"]

        response = self.client.lookup_events(**params)
        
        events = []
        for event in response.get("Events", []):
            events.append({
                "event_id": event.get("EventId"),
                "event_name": event.get("EventName"),
                "read_only": event.get("ReadOnly"),
                "access_key_id": event.get("AccessKeyId"),
                "event_time": event.get("EventTime").isoformat() if event.get("EventTime") else None,
                "event_source": event.get("EventSource"),
                "username": event.get("Username"),
                "resources": event.get("Resources", []),
                "cloud_trail_event": event.get("CloudTrailEvent")
            })

        return {
            "events": events,
            "total_count": len(events),
            "next_token": response.get("NextToken")
        }