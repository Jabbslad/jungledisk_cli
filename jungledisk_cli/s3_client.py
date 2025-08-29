"""S3 client module for interacting with JungleDisk buckets."""

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from typing import List, Dict, Optional, Any
import logging

logger = logging.getLogger(__name__)


class JungleDiskS3Client:
    """Client for interacting with JungleDisk S3 buckets."""
    
    def __init__(self, access_key: str, secret_key: str, bucket_name: str, region: str = 'us-east-1'):
        """Initialize S3 client with credentials.
        
        Args:
            access_key: AWS access key ID
            secret_key: AWS secret access key
            bucket_name: Name of the S3 bucket
            region: AWS region (default: us-east-1)
        """
        self.bucket_name = bucket_name
        
        # Configure connection pooling for better performance
        config = Config(
            max_pool_connections=20,  # Increase from default of 10
            retries={
                'max_attempts': 3,
                'mode': 'adaptive'  # Adaptive retry mode
            },
            read_timeout=60,  # Socket read timeout
            connect_timeout=10  # Socket connect timeout
        )
        
        self.s3_client = boto3.client(
            's3',
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region,
            config=config
        )
        
    def list_objects(self, prefix: str = '', delimiter: str = '/') -> Dict[str, Any]:
        """List objects in the S3 bucket with given prefix.
        
        Args:
            prefix: Prefix to filter objects
            delimiter: Delimiter for grouping keys
            
        Returns:
            Dictionary containing objects and common prefixes
        """
        try:
            response = self.s3_client.list_objects_v2(
                Bucket=self.bucket_name,
                Prefix=prefix,
                Delimiter=delimiter
            )
            return response
        except ClientError as e:
            logger.error(f"Error listing objects: {e}")
            raise
            
    def get_object_metadata(self, key: str) -> Dict[str, Any]:
        """Get metadata for a specific object.
        
        Args:
            key: S3 object key
            
        Returns:
            Dictionary containing object metadata
        """
        try:
            response = self.s3_client.head_object(
                Bucket=self.bucket_name,
                Key=key
            )
            return response.get('Metadata', {})
        except ClientError as e:
            logger.error(f"Error getting object metadata for {key}: {e}")
            return {}
            
    def download_object(self, key: str) -> bytes:
        """Download an object from S3.
        
        Args:
            key: S3 object key
            
        Returns:
            Object content as bytes
        """
        try:
            response = self.s3_client.get_object(
                Bucket=self.bucket_name,
                Key=key
            )
            return response['Body'].read()
        except ClientError as e:
            logger.error(f"Error downloading object {key}: {e}")
            raise