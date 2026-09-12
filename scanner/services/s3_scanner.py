import boto3

from models.scan_result import ScanResult


class S3Scanner:

    def __init__(self):
        self.s3 = boto3.client("s3")

    def scan(self):
        response = self.s3.list_buckets()

        scan_results = []

        for bucket in response["Buckets"]:
            bucket_name = bucket["Name"]

            # Get region
            location = self.s3.get_bucket_location(
                Bucket=bucket_name
            )

            region = (
                location["LocationConstraint"]
                or "us-east-1"
            )

            # Get Public Access Block configuration
            try:
                public_access = self.s3.get_public_access_block(
                    Bucket=bucket_name
                )

                public_access_config = (
                    public_access[
                        "PublicAccessBlockConfiguration"
                    ]
                )

            except self.s3.exceptions.NoSuchPublicAccessBlockConfiguration:
                public_access_config = None

            # Get versioning
            versioning = self.s3.get_bucket_versioning(
                Bucket=bucket_name
            )

            versioning_status = versioning.get(
                "Status",
                "Disabled"
            )

            # Get encryption
            try:
                self.s3.get_bucket_encryption(
                    Bucket=bucket_name
                )

                encryption_enabled = True

            except self.s3.exceptions.ServerSideEncryptionConfigurationNotFoundError:
                encryption_enabled = False

            # Get access logging
            logging_response = self.s3.get_bucket_logging(
                Bucket=bucket_name
            )

            logging_enabled = bool(
                logging_response.get("LoggingEnabled")
            )

            # Create ScanResult
            scan_result = ScanResult(
                service="s3",
                resource_id=bucket_name,
                region=region,
                configuration={
                    "public_access": public_access_config,
                    "versioning": versioning_status,
                    "encryption": encryption_enabled,
                    "logging": logging_enabled
                }
            )

            scan_results.append(scan_result)

        return scan_results