from models.finding import Finding


def check_public_ip(instance_id, public_ip):
    """
    Check whether an EC2 instance has a public IP address.
    """

    if public_ip:
        return Finding(
            rule_id="EC2_PUBLIC_IP",
            service="ec2",
            resource_id=instance_id,
            severity="MEDIUM",
            status="FAIL",
            message="EC2 instance has a public IP address.",
            description=(
                "The EC2 instance is directly reachable through a "
                "public IP address, increasing its exposure to the internet."
            ),
            remediation=(
                "Remove the public IP if internet access is not required. "
                "Use private networking and controlled access such as "
                "a VPN, bastion host, or AWS Systems Manager."
            )
        )

    return Finding(
        rule_id="EC2_PUBLIC_IP",
        service="ec2",
        resource_id=instance_id,
        severity="INFO",
        status="PASS",
        message="EC2 instance does not have a public IP address.",
        description=(
            "The EC2 instance does not have a public IPv4 address, "
            "reducing direct exposure to the internet."
        ),
        remediation="No remediation required."
    )


def check_security_group_rules(instance_id, security_group_rules):
    """
    Check whether an EC2 instance allows unrestricted SSH or RDP access.
    """

    exposed_services = []

    for security_group in security_group_rules:

        for inbound_rule in security_group["inbound_rules"]:

            protocol = inbound_rule["protocol"]
            from_port = inbound_rule["from_port"]
            to_port = inbound_rule["to_port"]
            cidr_ranges = inbound_rule["cidr_ranges"]

            if protocol != "tcp" or "0.0.0.0/0" not in cidr_ranges:
                continue

            if from_port is None or to_port is None:
                continue

            if from_port <= 22 <= to_port:
                exposed_services.append("SSH")

            if from_port <= 3389 <= to_port:
                exposed_services.append("RDP")

    exposed_services = list(dict.fromkeys(exposed_services))

    if exposed_services:
        exposed_service_message = " and ".join(exposed_services)

        return Finding(
            rule_id="EC2_SECURITY_GROUP",
            service="ec2",
            resource_id=instance_id,
            severity="HIGH",
            status="FAIL",
            message=(
                f"EC2 instance allows unrestricted "
                f"{exposed_service_message} access."
            ),
            description=(
                f"One or more attached security groups allow "
                f"{exposed_service_message} traffic from 0.0.0.0/0. "
                "This exposes remote administrative services to the internet."
            ),
            remediation=(
                "Remove the 0.0.0.0/0 inbound rule and restrict access to "
                "trusted IP addresses, a VPN, or a bastion host."
            )
        )

    return Finding(
        rule_id="EC2_SECURITY_GROUP",
        service="ec2",
        resource_id=instance_id,
        severity="INFO",
        status="PASS",
        message=(
            "EC2 instance does not allow unrestricted SSH or RDP access."
        ),
        description=(
            "No attached security group permits SSH port 22 or RDP port "
            "3389 from 0.0.0.0/0."
        ),
        remediation="No remediation required."
    )