class RiskEngine:

    SEVERITY_SCORES = {
        "CRITICAL": 10,
        "HIGH": 7,
        "MEDIUM": 4,
        "LOW": 2,
        "INFO": 0,
    }

    def calculate_score(self, finding):
        severity = finding.severity

        return self.SEVERITY_SCORES.get(severity, 0)

    def calculate_findings(self, findings):
        calculated_findings = []

        for finding in findings:
            calculated_findings.append(
                {
                    "rule_id": finding.rule_id,
                    "service": finding.service,
                    "resource_id": finding.resource_id,
                    "severity": finding.severity,
                    "status": finding.status,
                    "message": finding.message,
                    "description": finding.description,
                    "remediation": finding.remediation,
                    "risk_score": self.calculate_score(finding),
                }
            )

        return calculated_findings
