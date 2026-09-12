"""initial schema: scans, resources, findings

Revision ID: 0001
Revises:
Create Date: 2026-09-12

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


scan_status = postgresql.ENUM(
    "RUNNING", "COMPLETED", "FAILED", name="scan_status", create_type=False
)
finding_severity = postgresql.ENUM(
    "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", name="finding_severity", create_type=False
)
finding_status = postgresql.ENUM(
    "PASS", "FAIL", name="finding_status", create_type=False
)


def upgrade() -> None:
    bind = op.get_bind()
    scan_status.create(bind, checkfirst=True)
    finding_severity.create(bind, checkfirst=True)
    finding_status.create(bind, checkfirst=True)

    op.create_table(
        "scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "status",
            scan_status,
            nullable=False,
            server_default="RUNNING",
        ),
        sa.Column("total_resources", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total_findings", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total_risk_score", sa.Integer(), nullable=False, server_default="0"),
    )

    op.create_table(
        "resources",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "scan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("service", sa.String(), nullable=False),
        sa.Column("resource_id", sa.String(), nullable=False),
        sa.Column("region", sa.String(), nullable=True),
        sa.Column("configuration", sa.JSON(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index("ix_resources_scan_id", "resources", ["scan_id"])
    op.create_index("ix_resources_service", "resources", ["service"])
    op.create_index("ix_resources_resource_id", "resources", ["resource_id"])
    op.create_index(
        "ix_resources_service_resource_id", "resources", ["service", "resource_id"]
    )

    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "scan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "resource_pk",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("resources.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("rule_id", sa.String(), nullable=False),
        sa.Column("service", sa.String(), nullable=False),
        sa.Column("resource_id", sa.String(), nullable=False),
        sa.Column("severity", finding_severity, nullable=False),
        sa.Column("status", finding_status, nullable=False),
        sa.Column("message", sa.String(), nullable=False),
        sa.Column("description", sa.String(), nullable=True),
        sa.Column("remediation", sa.String(), nullable=True),
        sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"])
    op.create_index("ix_findings_resource_pk", "findings", ["resource_pk"])
    op.create_index("ix_findings_rule_id", "findings", ["rule_id"])
    op.create_index("ix_findings_service", "findings", ["service"])
    op.create_index("ix_findings_resource_id", "findings", ["resource_id"])
    op.create_index("ix_findings_severity", "findings", ["severity"])
    op.create_index("ix_findings_status", "findings", ["status"])


def downgrade() -> None:
    op.drop_table("findings")
    op.drop_table("resources")
    op.drop_table("scans")

    finding_status.drop(op.get_bind(), checkfirst=True)
    finding_severity.drop(op.get_bind(), checkfirst=True)
    scan_status.drop(op.get_bind(), checkfirst=True)
