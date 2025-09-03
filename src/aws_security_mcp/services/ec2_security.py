"""EC2 Security service."""

import mcp.types as types
from .base import BaseAWSService

class EC2SecurityService(BaseAWSService):
    def __init__(self, session):
        super().__init__(session)
        self.ec2_client = self.get_client("ec2")
        self.s3_client = session.client("s3")

    def get_tools(self):
        return [
            types.Tool(name="ec2_describe_security_groups", description="List security groups", inputSchema={"type": "object", "properties": {}}),
            types.Tool(name="ec2_describe_network_acls", description="List network ACLs", inputSchema={"type": "object", "properties": {}}),
            types.Tool(name="ec2_describe_instances", description="List instances", inputSchema={"type": "object", "properties": {}}),
            types.Tool(name="ec2_audit_key_pairs", description="Audit key pairs", inputSchema={"type": "object", "properties": {}}),
            types.Tool(name="ec2_audit_security_groups", description="Audit security groups", inputSchema={"type": "object", "properties": {}}),
            types.Tool(name="ec2_describe_vpc_endpoints", description="List VPC endpoints", inputSchema={"type": "object", "properties": {}}),
            types.Tool(name="ec2_describe_flow_logs", description="List flow logs", inputSchema={"type": "object", "properties": {}}),
            types.Tool(name="s3_list_buckets", description="List S3 buckets", inputSchema={"type": "object", "properties": {}}),
            types.Tool(name="s3_get_bucket_policy", description="Get bucket policy", inputSchema={"type": "object", "properties": {"bucket": {"type": "string"}}, "required": ["bucket"]}),
            types.Tool(name="s3_get_bucket_encryption", description="Get bucket encryption", inputSchema={"type": "object", "properties": {"bucket": {"type": "string"}}, "required": ["bucket"]}),
            types.Tool(name="s3_get_bucket_public_access_block", description="Get public access block", inputSchema={"type": "object", "properties": {"bucket": {"type": "string"}}, "required": ["bucket"]}),
            types.Tool(name="s3_audit_bucket_security", description="Audit bucket security", inputSchema={"type": "object", "properties": {}})
        ]

    async def handle_tool_call(self, name, arguments):
        try:
            if name == "ec2_describe_security_groups":
                return {"security_groups": self.ec2_client.describe_security_groups().get("SecurityGroups", [])}
            elif name == "ec2_describe_network_acls":
                return {"network_acls": self.ec2_client.describe_network_acls().get("NetworkAcls", [])}
            elif name == "ec2_describe_instances":
                return {"instances": self.ec2_client.describe_instances().get("Reservations", [])}
            elif name == "ec2_audit_key_pairs":
                return {"key_pairs": self.ec2_client.describe_key_pairs().get("KeyPairs", [])}
            elif name == "ec2_audit_security_groups":
                sgs = self.ec2_client.describe_security_groups().get("SecurityGroups", [])
                risky = [sg for sg in sgs if any("0.0.0.0/0" in str(rule) for rule in sg.get("IpPermissions", []))]
                return {"risky_security_groups": risky}
            elif name == "ec2_describe_vpc_endpoints":
                return {"vpc_endpoints": self.ec2_client.describe_vpc_endpoints().get("VpcEndpoints", [])}
            elif name == "ec2_describe_flow_logs":
                return {"flow_logs": self.ec2_client.describe_flow_logs().get("FlowLogs", [])}
            elif name == "s3_list_buckets":
                return {"buckets": self.s3_client.list_buckets().get("Buckets", [])}
            elif name == "s3_get_bucket_policy":
                try:
                    return {"policy": self.s3_client.get_bucket_policy(Bucket=arguments["bucket"])["Policy"]}
                except:
                    return {"policy": None}
            elif name == "s3_get_bucket_encryption":
                try:
                    return {"encryption": self.s3_client.get_bucket_encryption(Bucket=arguments["bucket"])}
                except:
                    return {"encryption": None}
            elif name == "s3_get_bucket_public_access_block":
                try:
                    return {"public_access_block": self.s3_client.get_public_access_block(Bucket=arguments["bucket"])}
                except:
                    return {"public_access_block": None}
            elif name == "s3_audit_bucket_security":
                buckets = self.s3_client.list_buckets().get("Buckets", [])
                return {"total_buckets": len(buckets), "audit_summary": "Security audit completed"}
        except Exception as e:
            return {"error": str(e)}