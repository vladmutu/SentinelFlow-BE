"""add_risk_assessment_to_scan_results

Revision ID: c1b5d7f9a6e4
Revises: e31f9c5d5a42
Create Date: 2026-04-20 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "c1b5d7f9a6e4"
down_revision: Union[str, Sequence[str], None] = "e31f9c5d5a42"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "scan_results",
        sa.Column("risk_assessment", sa.JSON(), nullable=True),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("scan_results", "risk_assessment")