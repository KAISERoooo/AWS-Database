import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload

from database.models import (
    Finding,
    FindingStatus,
    Resource,
    Scan,
    ScanStatus,
    Severity,
)


def create_scan(db: Session) -> Scan:

    scan = Scan(
        status=ScanStatus.RUNNING
    )

    db.add(scan)
    db.flush()

    return scan


def complete_scan(
    db: Session,
    scan_id: uuid.UUID,
    total_resources: int,
    total_findings: int,
    total_risk_score: int,
) -> Optional[Scan]:

    scan = db.get(Scan, scan_id)

    if scan is None:
        return None

    scan.status = ScanStatus.COMPLETED
    scan.total_resources = total_resources
    scan.total_findings = total_findings
    scan.total_risk_score = total_risk_score
    scan.completed_at = datetime.now(timezone.utc)

    db.flush()

    return scan


def fail_scan(
    db: Session,
    scan_id: uuid.UUID,
) -> Optional[Scan]:

    scan = db.get(Scan, scan_id)

    if scan is None:
        return None

    scan.status = ScanStatus.FAILED
    scan.completed_at = datetime.now(timezone.utc)

    db.flush()

    return scan


def get_scan(
    db: Session,
    scan_id: uuid.UUID,
) -> Optional[Scan]:

    return db.get(Scan, scan_id)


def list_scans(
    db: Session,
    limit: int = 50,
    offset: int = 0,
) -> list[Scan]:

    stmt = (
        select(Scan)
        .order_by(Scan.started_at.desc())
        .limit(limit)
        .offset(offset)
    )

    return list(db.scalars(stmt))


def create_resource(
    db: Session,
    scan_id: uuid.UUID,
    service: str,
    resource_id: str,
    region: Optional[str],
    configuration: dict,
) -> Resource:

    resource = Resource(
        scan_id=scan_id,
        service=service,
        resource_id=resource_id,
        region=region,
        configuration=configuration,
    )

    db.add(resource)
    db.flush()

    return resource


def get_resource(
    db: Session,
    resource_pk: uuid.UUID,
) -> Optional[Resource]:

    return db.get(Resource, resource_pk)


def list_resources(
    db: Session,
    service: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> list[Resource]:

    stmt = select(Resource)

    if service:
        stmt = stmt.where(
            Resource.service == service
        )

    stmt = (
        stmt
        .order_by(Resource.created_at.desc())
        .limit(limit)
        .offset(offset)
    )

    return list(db.scalars(stmt))


def create_finding(
    db: Session,
    scan_id: uuid.UUID,
    resource: Resource,
    finding_dict: dict,
) -> Finding:

    finding = Finding(
        scan_id=scan_id,
        resource_pk=resource.id,

        rule_id=finding_dict["rule_id"],
        service=finding_dict["service"],
        resource_id=finding_dict["resource_id"],

        severity=Severity(
            finding_dict["severity"]
        ),

        status=FindingStatus(
            finding_dict["status"]
        ),

        message=finding_dict["message"],
        description=finding_dict.get("description"),
        remediation=finding_dict.get("remediation"),

        risk_score=finding_dict.get(
            "risk_score",
            0
        ),
    )

    db.add(finding)
    db.flush()

    return finding


def get_finding(
    db: Session,
    finding_id: uuid.UUID,
) -> Optional[Finding]:

    return db.get(Finding, finding_id)


def list_findings(
    db: Session,
    severity: Optional[str] = None,
    service: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> list[Finding]:

    stmt = select(Finding)

    if severity:
        stmt = stmt.where(
            Finding.severity == Severity(severity)
        )

    if service:
        stmt = stmt.where(
            Finding.service == service
        )

    if status:
        stmt = stmt.where(
            Finding.status == FindingStatus(status)
        )

    stmt = (
        stmt
        .order_by(Finding.created_at.desc())
        .limit(limit)
        .offset(offset)
    )

    return list(db.scalars(stmt))


def get_finding_with_resource(
    db: Session,
    finding_id: uuid.UUID,
) -> Optional[Finding]:
    """
    Fetch a finding together with its related Resource, eagerly loaded so
    the caller (e.g. the FastAPI finding-detail endpoint) can read
    finding.resource without a second query.
    """

    stmt = (
        select(Finding)
        .where(Finding.id == finding_id)
        .options(joinedload(Finding.resource))
    )

    return db.scalars(stmt).first()


def list_findings_for_scan(
    db: Session,
    scan_id: uuid.UUID,
) -> list[Finding]:

    stmt = (
        select(Finding)
        .where(Finding.scan_id == scan_id)
        .order_by(Finding.risk_score.desc())
    )

    return list(db.scalars(stmt))


def get_dashboard_summary(
    db: Session,
) -> dict:

    total_resources = (
        db.scalar(
            select(func.count(Resource.id))
        )
        or 0
    )

    total_findings = (
        db.scalar(
            select(func.count(Finding.id))
        )
        or 0
    )

    total_risk_score = (
        db.scalar(
            select(func.sum(Finding.risk_score))
        )
        or 0
    )

    severity_counts = {}

    stmt = (
        select(
            Finding.severity,
            func.count(Finding.id),
        )
        .group_by(Finding.severity)
    )

    for severity, count in db.execute(stmt):
        severity_counts[severity.value] = count

    return {
        "total_resources": total_resources,
        "total_findings": total_findings,
        "total_risk_score": total_risk_score,
        "severity_counts": severity_counts,
    }