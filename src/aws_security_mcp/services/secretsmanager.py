"""Secrets Manager service."""

import mcp.types as types
from .base import BaseAWSService

class SecretsManagerService(BaseAWSService):
    def __init__(self, session):
        super().__init__(session)
        self.client = self.get_client("secretsmanager")

    def get_tools(self):
        return [
            types.Tool(name="secretsmanager_list_secrets", description="List secrets", inputSchema={"type": "object", "properties": {}}),
            types.Tool(name="secretsmanager_describe_secret", description="Get secret details", inputSchema={"type": "object", "properties": {"secret_id": {"type": "string"}}, "required": ["secret_id"]}),
            types.Tool(name="secretsmanager_get_resource_policy", description="Get resource policy", inputSchema={"type": "object", "properties": {"secret_id": {"type": "string"}}, "required": ["secret_id"]})
        ]

    async def handle_tool_call(self, name, arguments):
        try:
            if name == "secretsmanager_list_secrets":
                return {"secrets": self.client.list_secrets().get("SecretList", [])}
            elif name == "secretsmanager_describe_secret":
    async def handle_tool_call(self, name, arguments):
        try:
            if name == "secretsmanager_list_secrets":
                secrets = self.client.list_secrets().get("SecretList", [])
                for secret in secrets:
                    # Check rotation status
                    if not secret.get("RotationEnabled"):
                        secret["security_warning"] = "Rotation not enabled"
                    
                    # Check encryption
                    if not secret.get("KmsKeyId"):
                        secret["security_warning"] = "Using default encryption key"
                    
                    # Check last accessed/modified dates
                    if secret.get("LastAccessedDate"):
                        days_since_access = (datetime.utcnow() - secret["LastAccessedDate"]).days
                        if days_since_access > 90:
                            secret["security_warning"] = f"Not accessed in {days_since_access} days"
                
                return {"secrets": secrets, "total": len(secrets)}
            elif name == "secretsmanager_describe_secret":
                secret = self.client.describe_secret(SecretId=arguments["secret_id"])
                # Add security assessment
                secret["security_assessment"] = {
                    "rotation_enabled": secret.get("RotationEnabled", False),
                    "using_custom_kms": bool(secret.get("KmsKeyId")),
                    "last_rotated": secret.get("LastRotatedDate"),
                    "last_accessed": secret.get("LastAccessedDate"),
                    "risk_level": "HIGH" if not secret.get("RotationEnabled") else "LOW"
                }
                return {"secret": secret}
            elif name == "secretsmanager_get_resource_policy":
                return {"policy": self.client.get_resource_policy(SecretId=arguments["secret_id"])}
        except Exception as e:
            return {"error": str(e)}
                return {"policy": self.client.get_resource_policy(SecretId=arguments["secret_id"])}
        except Exception as e:
            return {"error": str(e)}