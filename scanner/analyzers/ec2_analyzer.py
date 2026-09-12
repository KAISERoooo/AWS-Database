from models.finding import Finding
from models.scan_result import ScanResult
from rules.ec2_rules import (
    check_public_ip,
    check_security_group_rules
)


class EC2Analyzer:

    def analyze(self, scan_results: list[ScanResult]) -> list[Finding]:
        findings = []

        for result in scan_results:

            # Check public IP
            public_ip = result.configuration.get(
                "public_ip"
            )

            public_ip_finding = check_public_ip(
                result.resource_id,
                public_ip
            )

            findings.append(public_ip_finding)

            # Check security group rules
            security_group_rules = result.configuration.get(
                "security_group_rules",
                []
            )

            security_group_finding = check_security_group_rules(
                result.resource_id,
                security_group_rules
            )

            findings.append(security_group_finding)

        return findings