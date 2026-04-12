"""empty message

Revision ID: 648a9b343d4d
Revises: d9b6d2c4f1a1
Create Date: 2026-04-12 21:55:11.698442

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '648a9b343d4d'
down_revision: Union[str, Sequence[str], None] = 'd9b6d2c4f1a1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
