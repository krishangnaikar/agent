import gzip
import logging
import time
import logging.handlers
import json
from io import BytesIO

import boto3
from datetime import datetime, timedelta

import requests


def setup_logger(log_file):
    logger = logging.getLogger('my_logger')
    logger.setLevel(logging.DEBUG)

    # Create a rotating file handler to create a new log file every 10 minutes
    handler = logging.handlers.TimedRotatingFileHandler(
        log_file,
        when="M",  # Rotate every 10 minutes
        interval=100,  # Rotate every 10 minutes
        backupCount=5  # Keep up to 5 backup log files
    )

    # Create a formatter
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)

    # Add the handler to the logger
    logger.addHandler(handler)
    return logger
def find_cloudtrail_bucket(credentials,logger):
    # Replace 'your_access_key', 'your_secret_key', and 'your_region' with your actual AWS credentials and region
    cloudtrail_client = boto3.client('cloudtrail', aws_access_key_id=credentials['aws_access_key_id'], aws_secret_access_key=credentials['aws_secret_access_key'],region_name='ap-south-1')

    response = cloudtrail_client.describe_trails()
    log_prefix = 'logs/'
    i=0
    for trail in response['trailList']:
        s3_bucket_name = trail.get('S3BucketName')
        logger.info(f"Getting into Bucket {s3_bucket_name}")
        if s3_bucket_name:
            s3_client = boto3.client(
                's3',
                aws_access_key_id=credentials['aws_access_key_id'], aws_secret_access_key=credentials['aws_secret_access_key'],region_name='ap-south-1'
            )
            time_threshold = datetime.utcnow() - timedelta(hours=24)

            # Format the timestamp according to S3 time format
            time_threshold_str = time_threshold.strftime('%Y-%m-%dT%H:%M:%SZ')

            # List objects in the access log bucket with a specific prefix
            responsee = s3_client.list_objects_v2(
                Bucket=s3_bucket_name
            )
            nextContinuoustoken = responsee.get("NextContinuationToken")
            for i in range(9):
                responsee = s3_client.list_objects_v2(
                    Bucket=s3_bucket_name,
                    ContinuationToken=nextContinuoustoken
                )
                nextContinuoustoken = responsee.get("NextContinuationToken")

            # Fetch and print access logs
            for obj in responsee.get('Contents', []):
                key = obj['Key']
                # print(f"Fetching logs from: s3://{s3_bucket_name}/{key}")

                # Download and process the log file content
                try:
                    log_content = s3_client.get_object(Bucket=s3_bucket_name, Key=key)['Body'].read()
                    with gzip.GzipFile(fileobj=BytesIO(log_content), mode='rb') as f:
                        decompressed_content = f.read().decode('utf-8')
                        i+=1
                        if "PutObject" in decompressed_content or "GetObject" in decompressed_content or "DeleteObject" in decompressed_content:
                            dcontent = json.loads(decompressed_content)
                            records = dcontent.get("Records", None)
                            if records:
                                for record in records:
                                    event_name = record.get("eventName")
                                    if event_name in ['GetObject', 'DeleteObject', 'PutObject']:
                                        user = record.get("userIdentity")
                                        username = "Unknown"
                                        if user and user.get("arn",None):
                                            username = user.get("arn").split("/")[-1]
                                        resources = record.get("resources")
                                        filename = "NA"
                                        for resource in resources:
                                            if resource.get("type") == 'AWS::S3::Object':
                                                filename = resource.get("ARN")
                                        operation = "Unkown"
                                        if event_name == "GetObject":
                                            operation = "Read"
                                        if event_name == "DeleteObject":
                                            operation = "Delete"
                                        if event_name == "PutObject":
                                            operation = "Create"
                                        audit_data = {
                                            "file_name": filename,
                                            "user_name": username,
                                            "operation": operation,
                                            "user_email": username
                                        }
                                        send_audit_data(aws_credentials, audit_data, logger)
                                        logger.info(
                                            f"The event is {event_name} user is {username} amd filename is {filename}")
                                        logger.info(key)
                                        logger.info(i)

                except Exception as exp:
                    logger.error(exp)
            while nextContinuoustoken:
                responsee = s3_client.list_objects_v2(
                    Bucket=s3_bucket_name,
                    ContinuationToken=nextContinuoustoken
                )
                nextContinuoustoken = responsee.get("NextContinuationToken")
                # Fetch and print access logs
                for obj in responsee.get('Contents', []):
                    key = obj['Key']
                    # print(f"Fetching logs from: s3://{s3_bucket_name}/{key}")

                    # Download and process the log file content  b
                    try:
                        log_content = s3_client.get_object(Bucket=s3_bucket_name, Key=key)['Body'].read()
                        with gzip.GzipFile(fileobj=BytesIO(log_content), mode='rb') as f:
                            decompressed_content = f.read().decode('utf-8')
                            i += 1
                            if "PutObject" in decompressed_content or "GetObject" in decompressed_content or "DeleteObject" in decompressed_content:
                                dcontent = json.loads(decompressed_content)
                                records = dcontent.get("Records",None)
                                if records:
                                    for record in records:
                                        event_name = record.get("eventName")
                                        if event_name in ['GetObject', 'DeleteObject', 'PutObject']:
                                            user = record.get("userIdentity")
                                            username = "Unknown"
                                            if user and user.get("arn",None):
                                                username = user.get("arn").split("/")[-1]
                                            resources = record.get("resources")
                                            filename = "NA"
                                            for resource in resources:
                                                if resource.get("type")=='AWS::S3::Object':
                                                    filename = resource.get("ARN")
                                            operation = "Unkown"
                                            if event_name=="GetObject":
                                                operation = "Read"
                                            if event_name=="DeleteObject":
                                                operation = "Delete"
                                            if event_name=="PutObject":
                                                operation = "Create"
                                            audit_data = {
                                                            "file_name": filename,
                                                            "user_name": username,
                                                            "operation": operation,
                                                            "user_email": username
                                                        }
                                            send_audit_data(aws_credentials,audit_data,logger)
                                            logger.info(f"The event is {event_name} user is {username} amd filename is {filename}")
                                            logger.info(key)
                                            logger.info(i)
                    except Exception as exp:
                        logger.error(exp)

            # print(f"CloudTrail logs are stored in the S3 bucket: {s3_bucket_name}")
            # process_s3_bucket_events(s3_bucket_name,credentials)
def send_audit_data(aws_credentials,audit_data,logger):
    try:
        url = aws_credentials.get("audit_url")
        audit_files = []
        audit_files.append(audit_data)
        payload_data = {
            "agent_uuid": aws_credentials["agent_uuid"],
            "audit_lines": audit_files
        }
        payload = json.dumps(payload_data)
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {aws_credentials["token"]}'
        }
        # Send a POST request with the JSON data
        response = requests.request("POST", url, headers=headers, data=payload)
        if response.status_code == 200:
            logger.info("Audit data updated succesfully")
        else:
            logger.error("Audit api failed")
    except Exception as exp:
        logger.error(f"An error occurred: {exp}")

def process_s3_bucket_events(s3_bucket_name,credentials):
    # Replace 'your_access_key', 'your_secret_key', and 'your_region' with your actual AWS credentials and region
    cloudtrail_client = boto3.client('cloudtrail',  aws_access_key_id=credentials['aws_access_key_id'], aws_secret_access_key=credentials['aws_secret_access_key'], region_name='ap-south-1')

    # Set the time range for which you want to retrieve CloudTrail events
    start_time = datetime.now() - timedelta(days=1)  # Adjust the time range as needed
    end_time = datetime.now()

    try:
        iter=1
        # Use the CloudTrail API to look up events related to the specified S3 bucket
        response = cloudtrail_client.lookup_events(
            StartTime=start_time,
            EndTime=end_time,
            MaxResults=10000 # Adjust this parameter based on your needs,
        )

        # Filter and print events related to data creation or update
        for event in response['Events']:
            if event.get('EventSource') == 's3.amazonaws.com' and event["EventName"] in ['GetObject', 'DeleteObject', 'PutObject']:
                print(f"Event at {event['EventTime']}: {event['EventName']}")
        next_token = response.get('NextToken', '')
        if not next_token:
            return
        else:
            while next_token:
                iter+=1
                response = cloudtrail_client.lookup_events(
                    StartTime=start_time,
                    EndTime=end_time,
                    MaxResults=1000000,
                    NextToken = next_token# Adjust this parameter based on your needs
                )

                # Filter and print events related to data creation or update
                for event in response['Events']:
                    if event.get('EventSource') == 's3.amazonaws.com' and event['EventName'] in ['GetObject', 'DeleteObject', 'PutObject']:
                        print(f"Event at {event['EventTime']}: {event['EventName']}", event["CloudTrailEvent"])
                        print(iter)
                next_token = response.get('NextToken', '')

        # s3_bucket_name = "trulnil-agent"
        # response = cloudtrail_client.lookup_events(
        #     StartTime=start_time,
        #     EndTime=end_time,
        #     EventSource='s3.amazonaws.com'
        # )
        #
        # # Filter and print events related to data creation or update
        # for event in response['Events']:
        #     if is_data_change_event(event):
        #         print(f"Event at {event['EventTime']}: {event['EventName']} - {event['Username']}")
    except cloudtrail_client.exceptions.InvalidTimeRangeException as e:
        print(f"Error: {e}")
def read_aws_credentials_from_json(file_path):
    try:
        with open(file_path, 'r') as file:
            credentials = json.load(file)
            return credentials
    except FileNotFoundError:
        print(f"Credentials file '{file_path}' not found.")
        return None
    except json.JSONDecodeError:
        print(f"Invalid JSON format in '{file_path}'.")
        return None

def is_data_change_event(event):
    # Add more conditions based on your specific requirements
    # Here, we're checking for S3 PutObject and CompleteMultipartUpload events
    return event['EventName'] in ['PutObject', 'CompleteMultipartUpload']

if __name__ == "__main__":
    credentials_file_path = "credentials.json"
    aws_credentials = read_aws_credentials_from_json(credentials_file_path)
    while "agent_uuid" not in aws_credentials:
        aws_credentials = read_aws_credentials_from_json(credentials_file_path)
        time.sleep(10)
    log_file = "AuditCheck.log"
    logger = setup_logger(log_file)
    if aws_credentials:
        while True:
            find_cloudtrail_bucket(aws_credentials,logger)
            time.sleep(86400)

