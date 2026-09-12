from analyzers.ec2_analyzer import EC2Analyzer
from services.ec2_scanner import EC2Scanner


def main():
    scanner = EC2Scanner()
    scan_results = scanner.scan()

    analyzer = EC2Analyzer()
    findings = analyzer.analyze(scan_results)

    print(f"EC2 resources found: {len(scan_results)}")
    print(f"Security findings: {len(findings)}")

    for finding in findings:
        print(
            f"rule_id={finding.rule_id}, "
            f"resource_id={finding.resource_id}, "
            f"severity={finding.severity}, "
            f"status={finding.status}, "
            f"message={finding.message}"
        )


if __name__ == "__main__":
    main()
