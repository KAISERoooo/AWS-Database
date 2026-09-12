from typing import Any, Protocol

from database.connection import session_scope
from database.crud import (
    complete_scan,
    create_finding,
    create_resource,
    create_scan,
)


class ScanResultLike(Protocol):
    """
    Structural type for whatever Member 1's scanner produces.

    We deliberately don't import scanner.models.scan_result.ScanResult
    here: the scanner package is run with `scanner/` on sys.path (its
    internal imports are `from models.scan_result import ...`, not
    `from scanner.models.scan_result import ...`), so a hard import from
    `database/` would only work by accident depending on which directory
    the process was launched from. Duck-typing on the four attributes
    that make up the integration contract keeps the two subsystems
    independently runnable/importable.
    """

    service: str
    resource_id: str
    region: str
    configuration: dict[str, Any]


def persist_scan(
    scan_results: list[ScanResultLike],
    calculated_findings: list[dict],
):

    with session_scope() as db:

        scan = create_scan(db)

        resources = {}

        for result in scan_results:

            resource = create_resource(
                db=db,
                scan_id=scan.id,
                service=result.service,
                resource_id=result.resource_id,
                region=result.region,
                configuration=result.configuration,
            )

            key = (
                result.service,
                result.resource_id,
            )

            resources[key] = resource

        for finding_dict in calculated_findings:

            key = (
                finding_dict["service"],
                finding_dict["resource_id"],
            )

            resource = resources.get(key)

            if resource is None:
                raise ValueError(
                    f"Resource not found for finding: {key}"
                )

            create_finding(
                db=db,
                scan_id=scan.id,
                resource=resource,
                finding_dict=finding_dict,
            )

        total_resources = len(resources)

        total_findings = len(
            calculated_findings
        )

        total_risk_score = sum(
            finding["risk_score"]
            for finding in calculated_findings
        )

        complete_scan(
            db=db,
            scan_id=scan.id,
            total_resources=total_resources,
            total_findings=total_findings,
            total_risk_score=total_risk_score,
        )

        return scan
    