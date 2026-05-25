"""add_scan_mode_to_scan_jobs

Revision ID: a1b2c3d4e5f6
Revises: 9024b65af779
Create Date: 2026-05-07 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "a1b2c3d4e5f6"
down_revision: Union[str, Sequence[str], None] = "9024b65af779"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "scan_jobs",
        sa.Column("scan_mode", sa.String(50), nullable=False, server_default="full"),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("scan_jobs", "scan_mode")
