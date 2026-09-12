import json

from analyzers.iam_analyzer import IAMAnalyzer
from analyzers.s3_analyzer import S3Analyzer
from services.iam_scanner import IAMScanner
from services.risk_engine import RiskEngine
from services.s3_scanner import S3Scanner


def main():
    s3_scanner = S3Scanner()
    s3_scan_results = s3_scanner.scan()

    s3_analyzer = S3Analyzer()
    s3_findings = s3_analyzer.analyze(s3_scan_results)

    iam_scanner = IAMScanner()
    iam_scan_results = iam_scanner.scan()

    iam_analyzer = IAMAnalyzer()
    iam_findings = iam_analyzer.analyze(iam_scan_results)

    combined_findings = s3_findings + iam_findings

    risk_engine = RiskEngine()
    calculated_findings = risk_engine.calculate_findings(combined_findings)

    for finding in calculated_findings:
        print(
            f"{finding['service']} | "
            f"{finding['resource_id']} | "
            f"{finding['rule_id']} | "
            f"risk_score={finding['risk_score']}"
        )

    total_risk_score = sum(
        finding["risk_score"]
        for finding in calculated_findings
    )

    print(f"\nTotal Risk Score: {total_risk_score}")

    print("\nCalculated Findings JSON")
    print("------------------------")

    print(json.dumps(calculated_findings, indent=4))


if __name__ == "__main__":
    main()
