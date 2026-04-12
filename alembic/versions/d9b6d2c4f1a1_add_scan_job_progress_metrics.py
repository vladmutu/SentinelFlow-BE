"""add_scan_job_progress_metrics

Revision ID: d9b6d2c4f1a1
Revises: 7a0334cdb03c
Create Date: 2026-04-11 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "d9b6d2c4f1a1"
down_revision: Union[str, Sequence[str], None] = "7a0334cdb03c"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "scan_jobs",
        sa.Column("total_dependency_nodes", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "scan_jobs",
        sa.Column("total_unique_packages", sa.Integer(), nullable=False, server_default="0"),
    )
    op.alter_column("scan_jobs", "total_dependency_nodes", server_default=None)
    op.alter_column("scan_jobs", "total_unique_packages", server_default=None)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("scan_jobs", "total_unique_packages")
    op.drop_column("scan_jobs", "total_dependency_nodes")
