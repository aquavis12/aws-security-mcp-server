"""Base service class for AWS services."""

from typing import Any, Dict
import boto3

class BaseAWSService:
    """Base class for AWS services."""

    def __init__(self, session: boto3.Session):
        """Initialize the AWS service."""
        self.session = session
        self.service_name = ""
        self._client = None

    @property
    def client(self):
        """Get the AWS service client."""
        if not self._client:
            self._client = self.session.client(self.service_name)
        return self._client

    def get_commands(self) -> Dict[str, Any]:
        """Get service commands."""
        return {}
