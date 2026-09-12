import json
from dataclasses import asdict

from services.s3_scanner import S3Scanner
from analyzers.s3_analyzer import S3Analyzer


print("AWS Security Scanner")
print("====================")


# Step 1: Scan AWS resources
scanner = S3Scanner()

scan_results = scanner.scan()

print("\nS3 Resources Found:", len(scan_results))


# Step 2: Analyze the scanned resources
analyzer = S3Analyzer()

findings = analyzer.analyze(scan_results)


# Step 3: Display findings
print("\nSecurity Findings")
print("-----------------")

for finding in findings:

    print("\nRule:", finding.rule_id)
    print("Service:", finding.service)
    print("Resource:", finding.resource_id)
    print("Severity:", finding.severity)
    print("Status:", finding.status)
    print("Message:", finding.message)


# Step 4: Convert scan results to JSON
print("\nScan Results JSON")
print("-----------------")

scan_results_json = [
    asdict(result)
    for result in scan_results
]

print(
    json.dumps(
        scan_results_json,
        indent=4
    )
)


# Step 5: Convert findings to JSON
print("\nFindings JSON")
print("-------------")

findings_json = [
    asdict(finding)
    for finding in findings
]

print(
    json.dumps(
        findings_json,
        indent=4
    )
)