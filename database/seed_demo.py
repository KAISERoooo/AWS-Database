"""
End-to-end sanity check for the database layer, using hand-built sample
data instead of a real AWS scan. This lets Member 2 verify persistence +
retrieval work without needing AWS credentials or Member 1's scanner
running, and gives Member 3/4/5 a known-good scan_id to build against
before the real pipeline is wired together.

Run with:
    python -m database.seed_demo
"""

from dataclasses import dataclass
from typing import Any

from database import crud
from database.connection import session_scope
from database.persistence import persist_scan
from database.serializers import finding_to_dict, scan_to_dict


@dataclass
class SampleScanResult:
    """Mimics the shape scanner.models.scan_result.ScanResult produces."""

    service: str
    resource_id: str
    region: str
    configuration: dict[str, Any]


SAMPLE_SCAN_RESULTS = [
    SampleScanResult(
        service="iam",
        resource_id="harsh",
        region="global",
        configuration={
            "username": "harsh",
            "console_access": True,
            "mfa_enabled": False,
        },
    ),
    SampleScanResult(
        service="s3",
        resource_id="my-public-bucket",
        region="us-east-1",
        configuration={
            "public_access": False,
            "versioning": "Disabled",
            "encryption": None,
        },
    ),
]

# This is the exact representative finding from PRD section 12
# (Integration Contract), plus one more to show multiple findings/severity
# levels rolling up into the dashboard totals correctly.
SAMPLE_CALCULATED_FINDINGS = [
    {
        "rule_id": "IAM_MFA",
        "service": "iam",
        "resource_id": "harsh",
        "severity": "HIGH",
        "status": "FAIL",
        "message": "IAM user does not have MFA enabled.",
        "description": "Multi-factor authentication adds a second layer "
        "of protection beyond a password.",
        "remediation": "Enable MFA for this IAM user in the AWS console.",
        "risk_score": 7,
    },
    {
        "rule_id": "S3_VERSIONING",
        "service": "s3",
        "resource_id": "my-public-bucket",
        "severity": "MEDIUM",
        "status": "FAIL",
        "message": "S3 bucket does not have versioning enabled.",
        "description": "Without versioning, overwritten or deleted "
        "objects cannot be recovered.",
        "remediation": "Enable versioning on this bucket.",
        "risk_score": 4,
    },
]


def main():
    scan = persist_scan(SAMPLE_SCAN_RESULTS, SAMPLE_CALCULATED_FINDINGS)
    scan_id = scan.id

    print("Persisted scan:")
    print(scan_to_dict(scan))

    with session_scope() as db:
        findings = crud.list_findings_for_scan(db, scan_id)

        print(f"\nFindings for scan {scan_id}:")
        for finding in findings:
            print(finding_to_dict(finding, include_resource=True))

        summary = crud.get_dashboard_summary(db)
        print("\nDashboard summary (across all scans in the DB):")
        print(summary)


if __name__ == "__main__":
    main()
