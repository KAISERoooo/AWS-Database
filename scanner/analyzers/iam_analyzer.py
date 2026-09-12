from models.finding import Finding
from models.scan_result import ScanResult
from rules.iam_rules import (
    check_mfa,
    check_console_access,
    check_access_keys,
)


class IAMAnalyzer:

    def analyze(self, scan_results: list[ScanResult]) -> list[Finding]:
        findings = []

        for result in scan_results:
            mfa_enabled = result.configuration.get("mfa_enabled")

            console_access = result.configuration.get("console_access")

            access_keys = result.configuration.get("access_keys", [])

            mfa_finding = check_mfa(
                result.resource_id,
                mfa_enabled,
            )

            console_access_finding = check_console_access(
                result.resource_id,
                console_access,
                mfa_enabled,
            )

            access_keys_finding = check_access_keys(
                result.resource_id,
                access_keys,
            )

            findings.append(mfa_finding)
            findings.append(console_access_finding)
            findings.append(access_keys_finding)

        return findings
