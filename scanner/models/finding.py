from dataclasses import dataclass


@dataclass
class Finding:
    rule_id: str
    service: str
    resource_id: str
    severity: str
    status: str
    message: str
    description: str
    remediation: str