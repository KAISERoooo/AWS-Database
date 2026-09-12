import enum
import uuid

from sqlalchemy import (
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from database.connection import Base


class ScanStatus(str, enum.Enum):
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class Severity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingStatus(str, enum.Enum):
    PASS = "PASS"
    FAIL = "FAIL"


class Scan(Base):

    __tablename__ = "scans"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    started_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    completed_at = Column(
        DateTime(timezone=True),
        nullable=True,
    )

    status = Column(
        Enum(ScanStatus, name="scan_status"),
        nullable=False,
        default=ScanStatus.RUNNING,
    )

    total_resources = Column(
        Integer,
        nullable=False,
        default=0,
    )

    total_findings = Column(
        Integer,
        nullable=False,
        default=0,
    )

    total_risk_score = Column(
        Integer,
        nullable=False,
        default=0,
    )

    resources = relationship(
        "Resource",
        back_populates="scan",
        cascade="all, delete-orphan",
    )

    findings = relationship(
        "Finding",
        back_populates="scan",
        cascade="all, delete-orphan",
    )


class Resource(Base):

    __tablename__ = "resources"
    __table_args__ = (
        Index(
            "ix_resources_service_resource_id",
            "service",
            "resource_id",
        ),
    )

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    scan_id = Column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    service = Column(
        String,
        nullable=False,
        index=True,
    )

    resource_id = Column(
        String,
        nullable=False,
        index=True,
    )

    region = Column(
        String,
        nullable=True,
    )

    configuration = Column(
        JSON,
        nullable=False,
    )

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    scan = relationship(
        "Scan",
        back_populates="resources",
    )

    findings = relationship(
        "Finding",
        back_populates="resource",
        cascade="all, delete-orphan",
    )


class Finding(Base):

    __tablename__ = "findings"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    scan_id = Column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    resource_pk = Column(
        UUID(as_uuid=True),
        ForeignKey("resources.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    rule_id = Column(
        String,
        nullable=False,
        index=True,
    )

    service = Column(
        String,
        nullable=False,
        index=True,
    )

    resource_id = Column(
        String,
        nullable=False,
        index=True,
    )

    severity = Column(
        Enum(Severity, name="finding_severity"),
        nullable=False,
        index=True,
    )

    status = Column(
        Enum(FindingStatus, name="finding_status"),
        nullable=False,
        index=True,
    )

    message = Column(
        String,
        nullable=False,
    )

    description = Column(
        String,
        nullable=True,
    )

    remediation = Column(
        String,
        nullable=True,
    )

    risk_score = Column(
        Integer,
        nullable=False,
        default=0,
    )

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    scan = relationship(
        "Scan",
        back_populates="findings",
    )

    resource = relationship(
        "Resource",
        back_populates="findings",
    )