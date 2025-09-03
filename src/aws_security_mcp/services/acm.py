"""ACM service."""

import mcp.types as types
from .base import BaseAWSService

class ACMService(BaseAWSService):
    def __init__(self, session):
        super().__init__(session)
        self.client = self.get_client("acm")

    def get_tools(self):
        return [
            types.Tool(name="acm_list_certificates", description="List certificates", inputSchema={"type": "object", "properties": {}}),
            types.Tool(name="acm_describe_certificate", description="Get certificate details", inputSchema={"type": "object", "properties": {"certificate_arn": {"type": "string"}}, "required": ["certificate_arn"]})
        ]

    async def handle_tool_call(self, name, arguments):
        try:
            if name == "acm_list_certificates":
                return {"certificates": self.client.list_certificates().get("CertificateSummaryList", [])}
            elif name == "acm_describe_certificate":
                return {"certificate": self.client.describe_certificate(CertificateArn=arguments["certificate_arn"])}
        except Exception as e:
            return {"error": str(e)}