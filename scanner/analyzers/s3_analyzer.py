from models.finding import Finding
from models.scan_result import ScanResult
from rules.s3_rules import (
    check_public_access,
    check_versioning,
    check_encryption,
    check_logging
)


class S3Analyzer:

    def analyze(self, scan_results: list[ScanResult]) -> list[Finding]:
        findings = []

        for result in scan_results:

            # Check public access
            public_access_config = result.configuration.get(
                "public_access"
            )

            public_access_finding = check_public_access(
                result.resource_id,
                public_access_config
            )

            findings.append(public_access_finding)

            # Check versioning
            versioning_status = result.configuration.get(
                "versioning"
            )

            versioning_finding = check_versioning(
                result.resource_id,
                versioning_status
            )

            findings.append(versioning_finding)

            # Check encryption
            encryption_enabled = result.configuration.get(
                "encryption"
            )

            encryption_finding = check_encryption(
                result.resource_id,
                encryption_enabled
            )

            findings.append(encryption_finding)

            # Check logging
            logging_enabled = result.configuration.get(
                "logging"
            )

            logging_finding = check_logging(
                result.resource_id,
                logging_enabled
            )

            findings.append(logging_finding)

        return findings