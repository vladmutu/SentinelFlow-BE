"""add_dependency_context_to_scan_tasks

Revision ID: 5a6d9c2bbf12
Revises: c1b5d7f9a6e4
Create Date: 2026-04-20 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "5a6d9c2bbf12"
down_revision: Union[str, Sequence[str], None] = "c1b5d7f9a6e4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "scan_tasks",
        sa.Column("dependency_context", sa.JSON(), nullable=True),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("scan_tasks", "dependency_context")