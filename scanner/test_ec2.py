import json
from dataclasses import asdict

from services.ec2_scanner import EC2Scanner


print("EC2 Security Scanner")
print("====================")


scanner = EC2Scanner()

scan_results = scanner.scan()

print("\nEC2 Resources Found:", len(scan_results))


print("\nEC2 Scan Results")
print("----------------")

for result in scan_results:

    print("\nService:", result.service)
    print("Instance:", result.resource_id)
    print("Region:", result.region)
    print("Configuration:", result.configuration)


print("\nEC2 Scan Results JSON")
print("--------------------")

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