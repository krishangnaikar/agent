import json
import logging
import logging.handlers
from io import BytesIO

import boto3
from botocore.exceptions import BotoCoreError
import psutil
import time
import requests
import pandas as pd

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

def get_client_name(credentials,logger):

    try:
        iam_client = boto3.client('iam',
                                  aws_access_key_id=credentials['aws_access_key_id'],
                                  aws_secret_access_key=credentials['aws_secret_access_key']
                                  )
        # Replace 'your-aws-account-id' with the AWS account ID you want to look up
        response = iam_client.get_account_authorization_details(Filter=['User'])
        return response
    except Exception as e:
        logger.error(f"An error occurred: {e}")
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
def is_fasta(content):
    lines = content.split('\n')
    for line in lines:
        if line.strip() == "":
            continue
        if not line.startswith('>'):
            return False
        break
    return True
def is_fastq(content):
    lines = content.split('\n')
    for i, line in enumerate(lines):
        line = line.strip()
        if i % 4 == 0:  # Check the header line
            if not line.startswith('@'):
                return False
    return True
def is_bam(content):
    # BAM files start with the binary BAM magic number (0x1f, 0x8b) and 'BAM\1'
    return content.startswith(b'BAM\x01')

def is_bai(content):
    # BAI files typically start with a known binary signature
    bai_signature = b'BAI\x01'
    return content.startswith(bai_signature)
def get_csv_data(bucket_name,file,credentials,logger):
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
        file_content = None
        response = s3_client.get_object(Bucket=bucket_name, Key=file_key)
        if file_key.lower().endswith(('.csv', '.txt')):
            # For CSV files
            file_content = pd.read_csv(response['Body'])
        elif file_key.lower().endswith(('.xls', '.xlsx')):
            # For Excel files
            # Create a seekable buffer around the S3 response content
            buffer = BytesIO(response['Body'].read())
            file_content = pd.read_excel(buffer)

        # Output the ACL for the file

        return file_content
    except Exception as exp:
        logger.error(f"An error occurred: {exp}")

def identify_file_type(bucket_name,file,credentials,logger):
    file_type, encryption_status ,compression_type= "Unknown", "Unknown" , "Uncompressed"
    try:
        file_data = file[0].split(".")
        if len(file_data)>1 and file_data[-1] in ["fasta","fa","fas"]:
            file_type = "FASTA"
            data = get_s3_file_details(bucket_name,file,credentials,logger)
            if is_fasta(data.decode('utf-8')):
                encryption_status = "Not Encrypted"
        if len(file_data)>1 and file_data[-1] in ["fastq","fq"]:
            file_type = "FASTAQ"
            data = get_s3_file_details(bucket_name,file,credentials,logger)
            if is_fastq(data.decode('utf-8')):
                encryption_status = "Not Encrypted"
        if len(file_data)>1 and file_data[-1] in ["bam"]:
            file_type = "BAM"
            data = get_s3_file_details(bucket_name,file,credentials,logger)
            if is_bam(data):
                encryption_status = "Not Encrypted"
        if len(file_data)>1 and file_data[-1] in ["bai"]:
            file_type = "BAM"
            data = get_s3_file_details(bucket_name,file,credentials,logger)
            if is_bai(data):
                encryption_status = "Not Encrypted"
        if len(file_data) > 1 and file_data[-1] in ["csv","xlsx"]:
            data = get_csv_data(bucket_name,file,credentials,logger)
            cols = data.columns.tolist()
            col_list = ["name", "height", "weight", "eye color", "hair type", "blood type", "skin color"]
            phi_score = 0
            for col in col_list:
                if col.lower() in cols:
                    phi_score+=1
            col_list = ["Cardholder name", "Credit/debit card account number", "Credit/debit card expiration date", "Credit/debit card verification number.", "Credit/debit card security code.", "Primary Account Number", "PAN","Magnetic stripe data","Cardholder name","Expiration date","Service code","Personal identification number","PIN"]
            pci_score = 0
            for col in col_list:
                if col in cols:
                    pci_score += 1
            col_list = ["Employee_ID", "Adress", "email", "Social Security number", "Driver's license number", "Passport Number", "Name","Address","Phone number","Email address"]
            pii_score = 0
            for col in col_list:
                if col in cols:
                    pii_score += 1
            if phi_score>pii_score and phi_score>pci_score:
                file_type = "PHI"
            if pii_score>phi_score and pii_score>pci_score:
                file_type = "PII"
            if pci_score>pii_score and pci_score>phi_score:
                file_type = "PCI"
            encryption_status = "Not Encrypted"

        if len(file_data) > 1 and file_data[-1].lower() in ["enc","ENC","p7m","zipx","veracrypt","bitlocker","dmcrypt","ecryptfs","luks","cry","crypt","aes","encr"]:
            encryption_status = "Encrypted"
        if len(file_data)>1 and file_data[-1] in ["gz","zip"]:
            compression_type = "GZ"
            encryption_status = "Not Encrypted"
            if len(file_data)>2:
                if file_data[-2] in ["fasta", "fa", "fas"]:
                    file_type = "FASTA"
                if file_data[-2] in ["fastq", "fq"]:
                    file_type = "FASTAQ"
                if file_data[-2] in ["bam", "bai"]:
                    file_type = "BAM"
                if file_data[-2] in ["enc","ENC","p7m","zipx","veracrypt","bitlocker","dmcrypt","ecryptfs","luks","cry","crypt","aes","encr"]:
                    encryption_status = "Encrypted"
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
            get_client_name(credentials,logger)
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

def send_user_data(data, aws_credentials, logger):
    try:
        agent_files = []
        url = aws_credentials.get("user_permission_url")
        response = get_client_name(aws_credentials,logger)
        if response and url:
            if "UserDetailList" in response:
                user_list = response["UserDetailList"]
                for user in user_list:
                    file_name = data["file_url"]
                    username = user["UserName"]
                    policy_list = user["UserPolicyList"]
                    permissions = []
                    for policy in policy_list:
                        if policy["PolicyName"]=="s3":
                            permissions = ["read","write"]
                            payload_data = {
                                "file_url": file_name,
                                "user_name": username,
                                "permissions": permissions
                            }
                            agent_files.append(payload_data)
            payload = json.dumps(agent_files)
            headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {aws_credentials["token"]}'
            }
            # Send a POST request with the JSON data
            response = requests.request("POST", url, headers=headers, data=payload)
            if response.status_code == 200:
                logger.info("Users updated succesfully")
            else:
                logger.error("Users api failed")
    except Exception as exp:
        logger.error(f"An error occurred: {exp}")

def send_dynamodb_user_data(data, aws_credentials, logger):
    try:
        agent_files = []
        url = aws_credentials.get("user_permission_url")
        response = get_client_name(aws_credentials,logger)
        if response and url:
            if "UserDetailList" in response:
                user_list = response["UserDetailList"]
                for user in user_list:
                    file_name = data["file_url"]
                    username = user["UserName"]
                    policy_list = user["UserPolicyList"]
                    attached_policy_list = user.get("AttachedManagedPolicies")
                    permissions = []
                    for policy in policy_list:
                        if "DynamoDB" in policy["PolicyName"]:
                            permissions = ["read","write"]
                            payload_data = {
                                "file_url": file_name,
                                "user_name": username,
                                "permissions": permissions
                            }
                            agent_files.append(payload_data)
                    for policy in attached_policy_list:
                        if "DynamoDB" in policy["PolicyName"]:
                            permissions = ["read","write"]
                            payload_data = {
                                "file_url": file_name,
                                "user_name": username,
                                "permissions": permissions
                            }
                            agent_files.append(payload_data)
            payload = json.dumps(agent_files)
            headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {aws_credentials["token"]}'
            }
            # Send a POST request with the JSON data
            response = requests.request("POST", url, headers=headers, data=payload)
            if response.status_code == 200:
                logger.info("Users updated succesfully")
            else:
                logger.error("Users api failed")
    except Exception as exp:
        logger.error(f"An error occurred: {exp}")
def get_dynamodb_data(credentials,logger):
    aws_access_key_id = credentials['aws_access_key_id']
    aws_secret_access_key = credentials['aws_secret_access_key']

    # Create a DynamoDB client with your credentials
    dynamodb = boto3.resource('dynamodb', region_name="us-west-1", aws_access_key_id=aws_access_key_id,
                              aws_secret_access_key=aws_secret_access_key)
    params = {'Limit': 10}
    table_name = credentials['dynamodb_table_name']
    table = dynamodb.Table(table_name)
    while True:
        response = table.scan(**params)
        items = response.get('Items', [])
        for item in items:
            logger.info(item)
            data = {
                      "file_url": item["sequence_id"],
                      "encryption_status": "Not encryted",
                      "file_type": item["type"],
                      "compression_type": "Not Compressed",
                      "storage_type": "Dynamodb"
                    }
            send_file_data(data, aws_credentials, logger)
            send_dynamodb_user_data(data, aws_credentials, logger)
        # Check if there are more items to retrieve
        if 'LastEvaluatedKey' in response:
            params['ExclusiveStartKey'] = response['LastEvaluatedKey']
        else:
            break
    # Continue with the rest of your code as before

    # item = {
    #     'key1': 'value1',
    #     'key2': 'value2',
    #     # Add more key-value pairs as needed
    # }
    # response = table.scan()
    #
    # # Print the items
    # items = response.get('Items', [])
    # for item in items:
    #     print(item)
    return items

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
                # get_s3_access_details(bucket_name,file,aws_credentials,logger)
                file_type , enryption_staus , compression_type =identify_file_type(bucket_name, file, aws_credentials, logger)
                data = {
                          "file_url": file[0],
                          "encryption_status": enryption_staus,
                          "file_type": file_type,
                          "compression_type": compression_type,
                          "storage_type": "s3"
                        }
                send_file_data(data, aws_credentials, logger)
                send_user_data(data, aws_credentials, logger)
                start+=1
            dynamo_db_files = get_dynamodb_data(aws_credentials,logger)
            time.sleep(7200)
