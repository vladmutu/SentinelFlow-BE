"""add_scan_tasks_and_processed_counter

Revision ID: e31f9c5d5a42
Revises: 648a9b343d4d
Create Date: 2026-04-13 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "e31f9c5d5a42"
down_revision: Union[str, Sequence[str], None] = "648a9b343d4d"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "scan_jobs",
        sa.Column("processed_packages", sa.Integer(), nullable=False, server_default="0"),
    )
    op.alter_column("scan_jobs", "processed_packages", server_default=None)

    op.create_table(
        "scan_tasks",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("job_id", sa.UUID(), nullable=False),
        sa.Column("package_name", sa.String(length=512), nullable=False),
        sa.Column("package_version", sa.String(length=255), nullable=False),
        sa.Column("ecosystem", sa.String(length=50), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("malware_score", sa.Float(), nullable=True),
        sa.Column("malware_status", sa.String(length=50), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["job_id"], ["scan_jobs.id"], name=op.f("fk_scan_tasks_job_id_scan_jobs"), ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scan_tasks")),
    )
    op.create_index("ix_scan_tasks_job_id", "scan_tasks", ["job_id"], unique=False)
    op.create_index("ix_scan_tasks_status", "scan_tasks", ["status"], unique=False)
    op.create_index("ix_scan_tasks_package", "scan_tasks", ["package_name", "package_version", "ecosystem"], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("ix_scan_tasks_package", table_name="scan_tasks")
    op.drop_index("ix_scan_tasks_status", table_name="scan_tasks")
    op.drop_index("ix_scan_tasks_job_id", table_name="scan_tasks")
    op.drop_table("scan_tasks")
    op.drop_column("scan_jobs", "processed_packages")
