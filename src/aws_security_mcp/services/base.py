"""Base service class."""

import boto3

class BaseAWSService:
    def __init__(self, session: boto3.Session):
        self.session = session
        self.client = None

    def get_client(self, service_name: str):
        if not self.client:
            self.client = self.session.client(service_name)
        return self.client