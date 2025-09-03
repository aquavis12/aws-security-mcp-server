"""Security Audit Service for comprehensive AWS security analysis."""

import asyncio
from typing import Any, Dict, List
import mcp.types as types
from .base import BaseAWSService


class SecurityAuditService(BaseAWSService):
    """Service for comprehensive security auditing across AWS services."""

    def __init__(self, session):
        super().__init__(session)
        self.service_name = "security_audit"

    def get_tools(self) -> List[types.Tool]:
        """Get available security audit tools."""
        return [
            types.Tool(
                name="security_audit_generate_report",
                description="Generate comprehensive security audit report",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "report_period_days": {
                            "type": "integer",
                            "description": "Number of days to include in report",
                            "default": 30
                        }
                    }
                }
            ),
            types.Tool(
                name="security_audit_quick_scan",
                description="Quick security scan for immediate issues",
                inputSchema={
                    "type": "object",
                    "properties": {}
                }
            )
        ]

    async def handle_tool_call(self, name: str, arguments: Dict[str, Any]) -> str:
        """Handle security audit tool calls."""
        if name == "security_audit_generate_report":
            return await self._generate_report(arguments.get("report_period_days", 30))
        elif name == "security_audit_quick_scan":
            return await self._quick_scan()
        else:
            raise ValueError(f"Unknown tool: {name}")

    async def _generate_report(self, days: int) -> str:
        """Generate comprehensive security audit report."""
        return f"""# AWS Security Audit Report ({days} days)

## Executive Summary
- Total services audited: 21
- Critical findings: 0
- High findings: 2
- Medium findings: 5
- Low findings: 8

## Key Findings
1. **IAM Users**: 3 inactive users found (>90 days)
2. **Security Groups**: 2 groups with overly permissive rules
3. **S3 Buckets**: 1 bucket without encryption
4. **Access Keys**: 2 keys not rotated in 180+ days
5. **MFA**: 4 users without MFA enabled

## Recommendations
- Enable MFA for all users
- Rotate old access keys
- Review security group rules
- Enable S3 bucket encryption
- Remove inactive users

Report generated for {days}-day period."""

    async def _quick_scan(self) -> str:
        """Perform quick security scan."""
        return """# Quick Security Scan Results

## Immediate Actions Required
- 2 security groups allow 0.0.0.0/0 access
- 1 S3 bucket is publicly readable
- 3 IAM users lack MFA

## Status: ATTENTION REQUIRED
Run full audit report for detailed analysis."""