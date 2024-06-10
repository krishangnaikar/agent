import time
import logging
import logging.handlers
import boto3
from botocore.exceptions import BotoCoreError
"""
This Python script checks the health of an AWS S3 bucket using provided AWS credentials stored in a JSON file. Here's a breakdown of the script:
Setup Logger: The setup_logger function configures a logger named "my_logger" to write log messages to a rotating log file. It rotates the log file every 10 minutes and keeps up to 5 backup log files.
Read AWS Credentials from JSON: The read_aws_credentials_from_json function reads AWS credentials from a JSON file. It returns the credentials as a dictionary or None if there are any errors (file not found or invalid JSON format).
Check S3 Bucket Health: The check_s3_bucket_health function takes AWS credentials, a bucket name, and a logger as input. It initializes an S3 client using the provided credentials and checks the health of the specified S3 bucket. It checks if the bucket exists, if it contains any objects, and logs the results.
Main Script Execution: In the __main__ block, the script reads AWS credentials from the specified JSON file, sets up a logger, and then enters a loop to periodically check the health of the S3 bucket every 10 seconds. If the AWS credentials are valid, the script continues to check the bucket health indefinitely.

"""
 
def setup_logger(log_file):
    logger = logging.getLogger('my_logger')
    logger.setLevel(logging.DEBUG)

    # Create a rotating file handler to create a new log file every 10 minutes
    handler = logging.handlers.TimedRotatingFileHandler(
        log_file,
        when="M",  # Rotate every 10 minutes
        interval=10,  # Rotate every 10 minutes
        backupCount=5  # Keep up to 5 backup log files
    )

    # Create a formatter
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)

    # Add the handler to the logger
    logger.addHandler(handler)
    return logger
def read_aws_credentials_from_json(file_path):
    try:
        import json
        with open(file_path, 'r') as file:
            credentials = json.load(file)
            return credentials
    except FileNotFoundError:
        print(f"Credentials file '{file_path}' not found.")
        return None
    except json.JSONDecodeError:
        print(f"Invalid JSON format in '{file_path}'.")
        return None

def check_s3_bucket_health(credentials, bucket_name,logger):
    try:
        # Initialize the S3 client with the provided credentials
        s3_client = boto3.client(
            's3',
            aws_access_key_id=credentials['aws_access_key_id'],
            aws_secret_access_key=credentials['aws_secret_access_key']
        )

        # Check if the bucket exists
        response = s3_client.head_bucket(Bucket=bucket_name)
        logger.info(f"Bucket {bucket_name} exists and is accessible.")

        # Check if you can list objects in the bucket
        response = s3_client.list_objects(Bucket=bucket_name)
        if 'Contents' in response:
            logger.info(f"Bucket {bucket_name} contains objects.")
        else:
            logger.info(f"Bucket {bucket_name} is empty.")

        # You can perform additional health checks here, such as verifying permissions, encryption settings, etc.

    except BotoCoreError as e:
        logger.error(f"An error occurred: {e}")

if __name__ == "__main__":
    credentials_file_path = "credentials.json"
    aws_credentials = read_aws_credentials_from_json(credentials_file_path)
    log_file = "healthCheck.log"
    logger = setup_logger(log_file)
    if aws_credentials:
        while True:
            bucket_name = aws_credentials.get("bucket_name")
            check_s3_bucket_health(aws_credentials, bucket_name,logger)
            time.sleep(10)
