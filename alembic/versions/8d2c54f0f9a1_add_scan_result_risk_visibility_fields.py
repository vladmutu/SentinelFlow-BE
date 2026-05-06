"""add_scan_result_risk_visibility_fields

Revision ID: 8d2c54f0f9a1
Revises: c1b5d7f9a6e4
Create Date: 2026-04-23 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "8d2c54f0f9a1"
down_revision: Union[str, Sequence[str], None] = "c1b5d7f9a6e4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column("scan_results", sa.Column("risk_breakdown", sa.JSON(), nullable=True))
    op.add_column("scan_results", sa.Column("advisory_references", sa.JSON(), nullable=True))
    op.add_column(
        "scan_results",
        sa.Column("risk_allowlisted", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "scan_results",
        sa.Column("risk_suppressed", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column("scan_results", sa.Column("risk_suppression_reason", sa.Text(), nullable=True))
    op.add_column("scan_results", sa.Column("analysis_status", sa.String(length=50), nullable=True))
    op.add_column("scan_results", sa.Column("analysis_coverage", sa.String(length=50), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("scan_results", "analysis_coverage")
    op.drop_column("scan_results", "analysis_status")
    op.drop_column("scan_results", "risk_suppression_reason")
    op.drop_column("scan_results", "risk_suppressed")
    op.drop_column("scan_results", "risk_allowlisted")
    op.drop_column("scan_results", "advisory_references")
    op.drop_column("scan_results", "risk_breakdown")