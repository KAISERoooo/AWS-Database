import boto3

from models.scan_result import ScanResult


class EC2Scanner:

    def __init__(self):
        self.ec2 = boto3.client("ec2")

    def scan(self):
        response = self.ec2.describe_instances()

        scan_results = []

        for reservation in response["Reservations"]:

            for instance in reservation["Instances"]:

                instance_id = instance["InstanceId"]

                state = instance["State"]["Name"]

                instance_type = instance["InstanceType"]

                public_ip = instance.get("PublicIpAddress")

                security_groups = []

                for security_group in instance["SecurityGroups"]:
                    security_groups.append({
                        "group_id": security_group["GroupId"],
                        "group_name": security_group["GroupName"]
                    })

                scan_result = ScanResult(
                    service="ec2",
                    resource_id=instance_id,
                    region=self.ec2.meta.region_name,
                    configuration={
                        "state": state,
                        "instance_type": instance_type,
                        "public_ip": public_ip,
                        "security_groups": security_groups
                    }
                )

                scan_results.append(scan_result)

        return scan_results
