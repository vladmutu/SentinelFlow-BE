"""merge heads

Revision ID: 9024b65af779
Revises: 5a6d9c2bbf12, 8d2c54f0f9a1
Create Date: 2026-05-06 15:59:56.178414

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '9024b65af779'
down_revision: Union[str, Sequence[str], None] = ('5a6d9c2bbf12', '8d2c54f0f9a1')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
