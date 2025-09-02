import boto3
import aioboto3
from typing import Any
import os

async def get_aws_client(service_name: str) -> Any:
    session = aioboto3.Session(
        region_name=os.environ.get('AWS_REGION', 'us-east-1'),
        aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
        aws_session_token=os.environ.get('AWS_SESSION_TOKEN')
    )
    async with session.client(service_name) as client:
        return client
