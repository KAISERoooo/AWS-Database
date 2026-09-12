"""
Optional helpers that turn ORM rows into plain dicts.

Member 3 (FastAPI) is free to write its own Pydantic response models
instead of using these -- they're provided purely as a convenience so the
exact field names/types from the integration contract don't have to be
re-typed by hand in the backend.
"""

from database.models import Finding, Resource, Scan


def scan_to_dict(scan: Scan) -> dict:
    return {
        "id": str(scan.id),
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "status": scan.status.value,
        "total_resources": scan.total_resources,
        "total_findings": scan.total_findings,
        "total_risk_score": scan.total_risk_score,
    }


def resource_to_dict(resource: Resource) -> dict:
    return {
        "id": str(resource.id),
        "scan_id": str(resource.scan_id),
        "service": resource.service,
        "resource_id": resource.resource_id,
        "region": resource.region,
        "configuration": resource.configuration,
        "created_at": resource.created_at.isoformat() if resource.created_at else None,
        "updated_at": resource.updated_at.isoformat() if resource.updated_at else None,
    }


def finding_to_dict(finding: Finding, include_resource: bool = False) -> dict:
    data = {
        "id": str(finding.id),
        "scan_id": str(finding.scan_id),
        "rule_id": finding.rule_id,
        "service": finding.service,
        "resource_id": finding.resource_id,
        "severity": finding.severity.value,
        "status": finding.status.value,
        "message": finding.message,
        "description": finding.description,
        "remediation": finding.remediation,
        "risk_score": finding.risk_score,
        "created_at": finding.created_at.isoformat() if finding.created_at else None,
    }

    if include_resource and finding.resource is not None:
        data["resource"] = resource_to_dict(finding.resource)

    return data
