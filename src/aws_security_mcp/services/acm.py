"""ACM service implementation for AWS Security MCP Server."""

import logging
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError
import mcp.types as types

logger = logging.getLogger(__name__)


class ACMService:
    """Service for handling ACM operations."""

    def __init__(self, session: boto3.Session):
        """Initialize the ACM service."""
        self.client = session.client("acm")

    def get_tools(self) -> List[types.Tool]:
        """Get available ACM tools."""
        return [
            types.Tool(
                name="acm_list_certificates",
                description="List SSL/TLS certificates",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "certificate_statuses": {
                            "type": "array",
                            "items": {
                                "type": "string",
                                "enum": ["PENDING_VALIDATION", "ISSUED", "INACTIVE", "EXPIRED", "VALIDATION_TIMED_OUT", "REVOKED", "FAILED"]
                            },
                            "description": "Filter certificates by status"
                        },
                        "includes": {
                            "type": "object",
                            "properties": {
                                "extended_key_usage": {
                                    "type": "array",
                                    "items": {"type": "string"}
                                },
                                "key_usage": {
                                    "type": "array", 
                                    "items": {"type": "string"}
                                },
                                "key_types": {
                                    "type": "array",
                                    "items": {"type": "string"}
                                }
                            }
                        },
                        "max_items": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 1000,
                            "default": 100
                        }
                    }
                }
            ),
            types.Tool(
                name="acm_describe_certificate",
                description="Get detailed information about a certificate",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "certificate_arn": {
                            "type": "string",
                            "description": "ARN of the certificate"
                        }
                    },
                    "required": ["certificate_arn"]
                }
            )
        ]

    async def handle_tool_call(self, name: str, arguments: Dict[str, Any]) -> Any:
        """Handle ACM tool calls."""
        try:
            if name == "acm_list_certificates":
                return await self._list_certificates(arguments)
            elif name == "acm_describe_certificate":
                return await self._describe_certificate(arguments)
            else:
                raise ValueError(f"Unknown ACM tool: {name}")

        except ClientError as e:
            logger.error(f"AWS client error in {name}: {e}")
            return {"error": str(e), "service": "acm", "operation": name}
        except Exception as e:
            logger.error(f"Unexpected error in {name}: {e}")
            return {"error": str(e), "service": "acm", "operation": name}

    async def _list_certificates(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """List certificates."""
        params = {}
        
        if "certificate_statuses" in arguments:
            params["CertificateStatuses"] = arguments["certificate_statuses"]
        if "includes" in arguments:
            params["Includes"] = arguments["includes"]
        if "max_items" in arguments:
            params["MaxItems"] = arguments["max_items"]

        response = self.client.list_certificates(**params)
        
        return {
            "certificate_summary_list": response.get("CertificateSummaryList", []),
            "next_token": response.get("NextToken")
        }

    async def _describe_certificate(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Describe a specific certificate."""
        certificate_arn = arguments["certificate_arn"]
        
        response = self.client.describe_certificate(CertificateArn=certificate_arn)
        
        certificate = response["Certificate"]
        
        return {
            "certificate_arn": certificate["CertificateArn"],
            "domain_name": certificate["DomainName"],
            "subject_alternative_names": certificate.get("SubjectAlternativeNames", []),
            "domain_validation_options": certificate.get("DomainValidationOptions", []),
            "serial": certificate.get("Serial"),
            "subject": certificate.get("Subject"),
            "issuer": certificate.get("Issuer"),
            "created_at": certificate.get("CreatedAt", {}).isoformat() if certificate.get("CreatedAt") else None,
            "issued_at": certificate.get("IssuedAt", {}).isoformat() if certificate.get("IssuedAt") else None,
            "imported_at": certificate.get("ImportedAt", {}).isoformat() if certificate.get("ImportedAt") else None,
            "status": certificate["Status"],
            "revoked_at": certificate.get("RevokedAt", {}).isoformat() if certificate.get("RevokedAt") else None,
            "revocation_reason": certificate.get("RevocationReason"),
            "not_before": certificate.get("NotBefore", {}).isoformat() if certificate.get("NotBefore") else None,
            "not_after": certificate.get("NotAfter", {}).isoformat() if certificate.get("NotAfter") else None,
            "key_algorithm": certificate.get("KeyAlgorithm"),
            "signature_algorithm": certificate.get("SignatureAlgorithm"),
            "in_use_by": certificate.get("InUseBy", []),
            "failure_reason": certificate.get("FailureReason"),
            "type": certificate.get("Type"),
            "key_usage": certificate.get("KeyUsages", []),
            "extended_key_usage": certificate.get("ExtendedKeyUsages", []),
            "certificate_transparency_logging_preference": certificate.get("CertificateTransparencyLoggingPreference"),
            "renewal_eligibility": certificate.get("RenewalEligibility"),
            "tags": certificate.get("Tags", [])
        }
