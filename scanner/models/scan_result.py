from dataclasses import dataclass
from typing import Any


@dataclass
class ScanResult:
    service: str
    resource_id: str
    region: str
    configuration: dict[str, Any]