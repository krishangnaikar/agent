import json
import logging
import logging.handlers
import boto3
from botocore.exceptions import BotoCoreError
import psutil
import time
import requests


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

def get_client_name_by_id(client_id,credentials,logger):

    try:
        iam_client = boto3.client('iam',
                                  aws_access_key_id=credentials['aws_access_key_id'],
                                  aws_secret_access_key=credentials['aws_secret_access_key']
                                  )
        # Replace 'your-aws-account-id' with the AWS account ID you want to look up
        aws_account_id = client_id
        response = iam_client.get_account_authorization_details(Filter=['User'])

        for user_detail in response.get('UserDetailList', []):
            if user_detail['Arn'].split(':')[4] == aws_account_id:
                user_name = user_detail['UserName']
                print(f"User Name: {user_name}")
                break  # Break after finding the user
        else:
            print(f"No user found with AWS account ID {aws_account_id}")
    except Exception as e:
        logger.error(f"An error occurred: {e}")
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

def register_user(data,logger):
    try:
        url = data.get("register_url")
        payload = json.dumps({
            "uuid": data["agent_uuid"],
            "version": "1",
            "health_status": "active",
            "ip_address": "127.0.0.1",
            "host_name": "sdf",
            "running_as_user_name": data["name"],
            "environment_settings": "sdf",
            "agent_metadata": "{\"asdsad\":\"asdasd\"}",
            "organization": data["organization_id"],
            "agent_state": "active"
        })
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {data["token"]}'
        }

        response = requests.request("POST", url, headers=headers, data=payload)
        return response
    except Exception as exp:
        logger.error(f"An error occurred: {exp}")

def send_system_data(agent_data,logger):
    try:
        url = agent_data.get("metric_url")
        cpu_usage = psutil.cpu_percent(interval=1)  # Get CPU usage for the last 1 second
        virtual_memory = psutil.virtual_memory()
        ram_usage = virtual_memory.percent
        disk_usage = psutil.disk_usage('/').percent
        logger.info(f"CPU usage is {cpu_usage}%")
        logger.info(f"Ram usage is {ram_usage}%")
        logger.info(f"Disk usage is {disk_usage}%")

        agent_metrics = []
        agent_metrics.append({
                    "metric_name": "CPU Usage",
                    "metric_value": float(cpu_usage),
                    "process_name": "cpu"
                })
        agent_metrics.append({
            "metric_name": "ram_usage",
            "metric_value": float(ram_usage),
            "process_name": "ram_usage"
        })
        agent_metrics.append({
            "metric_name": "disk_usage",
            "metric_value": float(disk_usage),
            "process_name": "disk_usage"
        })
        data = {
            "agent_uuid": agent_data["agent_uuid"],
            "agent_metrics": agent_metrics
        }
        payload = json.dumps(data)
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {agent_data["token"]}'
        }
        # Send a POST request with the JSON data
        response = requests.request("POST", url, headers=headers, data=payload)
        if response.status_code==200:
            logger.info("Status updated succesfully")
        else:
            logger.error("Metrics api failed")

    except Exception as exp:
        logger.error(f"An error occurred: {exp}")
def lsit_all_s3_data(bucket,credentials,logger):
    try:
        s3_client = boto3.client(
            's3',
            aws_access_key_id=credentials['aws_access_key_id'],
            aws_secret_access_key=credentials['aws_secret_access_key']
        )

        # Replace 'your-bucket-name' with your actual S3 bucket name
        bucket_name = bucket

        # List all objects in the bucket
        objects = s3_client.list_objects_v2(Bucket=bucket_name)

        # Iterate through the objects and print their keys
        bucket_files = []
        for obj in objects.get('Contents', []):
            bucket_files.append((obj["Key"],obj['Size']))
            logger.info(f"File: {obj['Key']} - Size: {obj['Size']} bytes")
        return bucket_files
    except Exception as exp:
        logger.error(f"An error occurred: {exp}")
        return []

def identify_file_type(bucket_name,file,credentials,logger):
    file_type, encryption_status ,compression_type= "Unknown", "Unknown" , "Uncompressed"
    try:
        file_data = file[0].split(".")
        if len(file_data)>1 and file_data[-1] in ["fasta","fa","fas"]:
            file_type = "FASTA"
            data = get_s3_file_details(bucket_name,file,credentials,logger)
        if len(file_data)>1 and file_data[-1] in ["fastq","fq"]:
            file_type = "FASTAQ"
            data = get_s3_file_details(bucket_name,file,credentials,logger)
        if len(file_data)>1 and file_data[-1] in ["bam","bai"]:
            file_type = "BAM"
            data = get_s3_file_details(bucket_name,file,credentials,logger)
        if len(file_data)>1 and file_data[-1] in ["gz","zip"]:
            compression_type = "GZ"
            encryption_status = "Encrypted"
            if len(file_data)>2:
                if file_data[-2] in ["fasta", "fa", "fas"]:
                    file_type = "FASTA"
                if file_data[-2] in ["fastq", "fq"]:
                    file_type = "FASTAQ"
                if file_data[-2] in ["bam", "bai"]:
                    file_type = "BAM"
            # data = get_s3_file_details(bucket_name,file,credentials,logger)
        logger.info(f"FILE type for File {file} is {file_type} and encryption status is {encryption_status}")
        return file_type, encryption_status, compression_type
    except Exception as exp:
        logger.error(f"An error occurred: {exp}")
        return file_type,encryption_status,compression_type

def get_s3_file_details(bucket_name,file,credentials,logger):
    # Initialize the Boto3 S3 client
    try:
        s3_client = boto3.client(
            's3',
            aws_access_key_id=credentials['aws_access_key_id'],
            aws_secret_access_key=credentials['aws_secret_access_key']
        )

        # Replace 'your-bucket-name' with your actual S3 bucket nam

        # Replace 'your-file-key' with the key of the file you want to query
        file_key = file[0]
        range_header = f"bytes={0}-{1000}"
        # List object ACL (Access Control List)
        response = s3_client.get_object(Bucket=bucket_name, Key=file_key, Range=range_header)

        # Output the ACL for the file
        file_content = response['Body'].read()

        # You can now work with the file content in memory
        # For example, print the first 100 characters
        logger.info(file_content[:100])
        return file_content
    except Exception as exp:
        logger.error(f"An error occurred: {exp}")

def get_s3_access_details(bucket_name,file,credentials,logger):
    # Initialize the Boto3 S3 client
    try:
        s3_client = boto3.client(
            's3',
            aws_access_key_id=credentials['aws_access_key_id'],
            aws_secret_access_key=credentials['aws_secret_access_key']
        )

        # Replace 'your-bucket-name' with your actual S3 bucket nam

        # Replace 'your-file-key' with the key of the file you want to query
        file_key = file[0]

        # List object ACL (Access Control List)
        file_acl = s3_client.get_object_acl(Bucket=bucket_name, Key=file_key)

        # Output the ACL for the file
        logger.info("File ACL:")
        for grant in file_acl['Grants']:
            get_client_name_by_id(grant.get("Grantee").get("ID"),credentials,logger)
            logger.info(grant)

        # List object policy
        file_policy = s3_client.get_bucket_policy(Bucket=bucket_name)

        # Output the policy for the file
        logger.info("\nFile Policy:")
        logger.info(file_policy['Policy'])
    except Exception as exp:
        logger.error(f"An error occurred: {exp}")
def send_file_data(data, aws_credentials, logger):
    try:
        url = aws_credentials.get("file_url")
        agent_files = []
        agent_files.append(data)
        payload_data = {
            "agent_uuid": aws_credentials["agent_uuid"],
            "agent_files": agent_files
        }
        payload = json.dumps(payload_data)
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {aws_credentials["token"]}'
        }
        # Send a POST request with the JSON data
        response = requests.request("POST", url, headers=headers, data=payload)
        if response.status_code == 200:
            logger.info("File updated succesfully")
        else:

            logger.error("File api failed")
    except Exception as exp:
        logger.error(f"An error occurred: {exp}")

if __name__ == "__main__":
    credentials_file_path = "credentials.json"
    aws_credentials = read_aws_credentials_from_json(credentials_file_path)
    while "agent_uuid" not in aws_credentials:
        aws_credentials = read_aws_credentials_from_json(credentials_file_path)
        time.sleep(10)
    log_file = "DataCheck.log"
    logger = setup_logger(log_file)
    if aws_credentials:
        while True:
            bucket_name = aws_credentials.get("bucket_name")
            bucket_files = lsit_all_s3_data(bucket_name,aws_credentials,logger)
            logger.info(f"Total list of files are {len(bucket_files)}")
            start = 1
            for file in bucket_files:
                logger.info(f"Starting data check for item {start} : {file}")
                get_s3_access_details(bucket_name,file,aws_credentials,logger)
                file_type , enryption_staus , compression_type =identify_file_type(bucket_name, file, aws_credentials, logger)
                data = {
                          "file_url": file[0],
                          "encryption_status": enryption_staus,
                          "file_type": file_type,
                          "compression_type": compression_type
                        }
                send_file_data(data, aws_credentials, logger)
                start+=1
            time.sleep(300)
