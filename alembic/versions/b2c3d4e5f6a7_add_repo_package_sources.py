"""add_repo_package_sources

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-05-27 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "b2c3d4e5f6a7"
down_revision: Union[str, Sequence[str], None] = "a1b2c3d4e5f6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "scan_jobs",
        sa.Column("package_source_hash", sa.String(64), nullable=True),
    )

    op.create_table(
        "repo_package_sources",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("owner", sa.String(255), nullable=False),
        sa.Column("repo_name", sa.String(255), nullable=False),
        sa.Column("ecosystem", sa.String(50), nullable=False),
        sa.Column("source_type", sa.String(100), nullable=False),
        sa.Column("source_content", sa.Text(), nullable=False),
        sa.Column("source_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_repo_package_sources_repo",
        "repo_package_sources",
        ["owner", "repo_name", "ecosystem"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ix_repo_package_sources_repo", table_name="repo_package_sources")
    op.drop_table("repo_package_sources")
    op.drop_column("scan_jobs", "package_source_hash")
