import json
from dataclasses import asdict

from services.iam_scanner import IAMScanner


print("IAM Security Scanner")
print("====================")


scanner = IAMScanner()

scan_results = scanner.scan()

print("\nIAM Users Found:", len(scan_results))


print("\nIAM Scan Results")
print("----------------")

for result in scan_results:

    print("\nService:", result.service)
    print("User:", result.resource_id)
    print("Region:", result.region)
    print("Configuration:", result.configuration)


print("\nIAM Scan Results JSON")
print("--------------------")

scan_results_json = [
    asdict(result)
    for result in scan_results
]

print(
    json.dumps(
        scan_results_json,
        indent=4,
        default=str
    )
)