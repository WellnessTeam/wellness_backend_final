# /app/utils/s3.py
import boto3
from botocore.exceptions import NoCredentialsError
from fastapi import HTTPException
from io import BytesIO
from dotenv import load_dotenv
import os
from core.config import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY

# Initialize S3 client
s3_client = boto3.client(
    's3',
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY
)

def upload_image_to_s3(image_bytes: BytesIO, bucket_name: str, file_name: str) -> str:
    """S3에 이미지를 업로드하고 URL을 반환하는 함수"""
    s3 = boto3.client('s3')
    try:
        s3.upload_fileobj(image_bytes, bucket_name, file_name)
        image_url = f"https://{bucket_name}.s3.amazonaws.com/{file_name}"
        return image_url
    except NoCredentialsError:
        raise HTTPException(status_code=500, detail="S3 credentials not available.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to upload file to S3: {str(e)}")
