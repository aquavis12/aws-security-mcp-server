#!/usr/bin/env python3
"""AWS Security MCP Server."""

import asyncio
import json
import logging
import os
from typing import Any, Dict, List

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from mcp.server import NotificationOptions, Server
from mcp.server.models import InitializationOptions
import mcp.server.stdio
import mcp.types as types

from .services.iam import IAMService
from .services.kms import KMSService
from .services.guardduty import GuardDutyService
from .services.securityhub import SecurityHubService
from .services.config import ConfigService
from .services.accessanalyzer import AccessAnalyzerService
from .services.cloudtrail import CloudTrailService
from .services.inspector import InspectorService
from .services.macie import MacieService
from .services.networkfirewall import NetworkFirewallService
from .services.secretsmanager import SecretsManagerService
from .services.shield import ShieldService
from .services.waf import WAFService
from .services.acm import ACMService
from .services.auditmanager import AuditManagerService
from .services.cloudwatch import CloudWatchService
from .services.ec2_security import EC2SecurityService
from .services.identitycenter import IdentityCenterService
from .services.verifiedaccess import VerifiedAccessService
from .services.vpclattice import VPCLatticeService
from .services.security_audit import SecurityAuditService


# Configure logging
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# MCP server instance
server = Server("aws-security-mcp-server")


class AWSSecurityMCPServer:
    """Main AWS Security MCP Server class."""

    def __init__(self):
        """Initialize the server with AWS clients and services."""
        self.region = os.getenv("AWS_REGION", os.getenv("AWS_DEFAULT_REGION", "us-east-1"))
        self.profile = os.getenv("AWS_PROFILE")
        
        # Initialize boto3 session
        try:
            self.session = boto3.Session(
                profile_name=self.profile,
                region_name=self.region
            )
            # Test credentials
            sts = self.session.client('sts')
            identity = sts.get_caller_identity()
            logger.info(f"Initialized AWS session for account: {identity.get('Account')} in region: {self.region}")
        except Exception as e:
            logger.error(f"Failed to initialize AWS session: {e}")
            raise
        
        # Initialize services
        self.services = self._initialize_services()
        
    def _initialize_services(self) -> Dict[str, Any]:
        """Initialize all AWS service handlers."""
        services = {}
        
        service_classes = {
            "iam": IAMService,
            "kms": KMSService,
            "guardduty": GuardDutyService,
            "securityhub": SecurityHubService,
            "config": ConfigService,
            "accessanalyzer": AccessAnalyzerService,
            "cloudtrail": CloudTrailService,
            "inspector": InspectorService,
            "macie": MacieService,
            "networkfirewall": NetworkFirewallService,
            "secretsmanager": SecretsManagerService,
            "shield": ShieldService,
            "waf": WAFService,
            "acm": ACMService,
            "auditmanager": AuditManagerService,
            "cloudwatch": CloudWatchService,
            "ec2_security": EC2SecurityService,
            "identitycenter": IdentityCenterService,
            "verifiedaccess": VerifiedAccessService,
            "vpclattice": VPCLatticeService,
            "security_audit": SecurityAuditService

        }
        
        for service_name, service_class in service_classes.items():
            try:
                services[service_name] = service_class(self.session)
                logger.debug(f"Initialized {service_name} service")
            except Exception as e:
                logger.warning(f"Failed to initialize {service_name} service: {e}")
                # Continue with other services
                
        logger.info(f"Initialized {len(services)} AWS services")
        return services

    def get_available_tools(self) -> List[types.Tool]:
        """Get all available tools from all services."""
        tools = []
        
        for service_name, service in self.services.items():
            try:
                service_tools = service.get_tools()
                tools.extend(service_tools)
                logger.debug(f"Added {len(service_tools)} tools from {service_name}")
            except Exception as e:
                logger.error(f"Failed to get tools from {service_name}: {e}")
                
        logger.info(f"Total available tools: {len(tools)}")
        return tools

    async def handle_tool_call(self, name: str, arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Handle tool calls by routing to appropriate service."""
        try:
            # Determine which service handles this tool
            service_name = self._get_service_for_tool(name)
            
            if service_name not in self.services:
                error_msg = f"Service {service_name} not available"
                logger.error(error_msg)
                return [types.TextContent(type="text", text=error_msg)]
            
            service = self.services[service_name]
            result = await service.handle_tool_call(name, arguments)
            
            if isinstance(result, str):
                return [types.TextContent(type="text", text=result)]
            elif isinstance(result, dict):
                return [types.TextContent(type="text", text=json.dumps(result, indent=2, default=str))]
            else:
                return [types.TextContent(type="text", text=str(result))]
                
        except (ClientError, BotoCoreError) as e:
            error_msg = f"AWS error for tool {name}: {e}"
            logger.error(error_msg)
            return [types.TextContent(type="text", text=error_msg)]
            
        except Exception as e:
            error_msg = f"Unexpected error for tool {name}: {e}"
            logger.error(error_msg)
            return [types.TextContent(type="text", text=error_msg)]

    def _get_service_for_tool(self, tool_name: str) -> str:
        """Determine which service handles a given tool."""
        service_prefixes = {
            "iam_": "iam",
            "kms_": "kms",
            "guardduty_": "guardduty",
            "securityhub_": "securityhub",
            "config_": "config",
            "accessanalyzer_": "accessanalyzer",
            "cloudtrail_": "cloudtrail",
            "inspector_": "inspector",
            "macie_": "macie",
            "networkfirewall_": "networkfirewall",
            "secretsmanager_": "secretsmanager",
            "shield_": "shield",
            "waf_": "waf",
            "acm_": "acm",
            "auditmanager_": "auditmanager",
            "cloudwatch_": "cloudwatch",
            "ec2_": "ec2_security",
            "s3_": "ec2_security",
            "identitycenter_": "identitycenter",
            "verifiedaccess_": "verifiedaccess",
            "vpclattice_": "vpclattice",
            "security_audit_": "security_audit"

        }
        
        for prefix, service in service_prefixes.items():
            if tool_name.startswith(prefix):
                return service
                
        raise ValueError(f"Unknown tool: {tool_name}")


# Initialize AWS server instance
aws_server = AWSSecurityMCPServer()


@server.list_tools()
async def list_tools() -> List[types.Tool]:
    """List available tools."""
    return aws_server.get_available_tools()


@server.call_tool()
async def call_tool(
    name: str, arguments: dict | None
) -> List[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    """Call a tool."""
    if arguments is None:
        arguments = {}
        
    return await aws_server.handle_tool_call(name, arguments)


async def main():
    """Main entry point."""
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="aws-security-mcp-server",
                server_version="1.0.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


if __name__ == "__main__":
    asyncio.run(main())
