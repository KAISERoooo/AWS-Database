import boto3

from models.scan_result import ScanResult


class IAMScanner:

    def __init__(self):
        self.iam = boto3.client("iam")

    def scan(self):
        response = self.iam.list_users()
        scan_results = []

        for user in response["Users"]:
            user_name = user["UserName"]
            user_id = user["UserId"]
            create_date = user["CreateDate"].isoformat()

            try:
                self.iam.get_login_profile(UserName=user_name)
                console_access = True
            except self.iam.exceptions.NoSuchEntityException:
                console_access = False

            mfa_response = self.iam.list_mfa_devices(UserName=user_name)
            mfa_enabled = len(mfa_response["MFADevices"]) > 0

            access_keys_response = self.iam.list_access_keys(UserName=user_name)
            access_keys = []

            for access_key in access_keys_response["AccessKeyMetadata"]:
                access_keys.append(
                    {
                        "access_key_id": access_key["AccessKeyId"],
                        "status": access_key["Status"],
                    }
                )

            scan_result = ScanResult(
                service="iam",
                resource_id=user_name,
                region="global",
                configuration={
                    "user_id": user_id,
                    "create_date": create_date,
                    "console_access": console_access,
                    "mfa_enabled": mfa_enabled,
                    "access_keys": access_keys,
                },
            )

            scan_results.append(scan_result)

        return scan_results
