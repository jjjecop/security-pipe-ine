"""add unique constraint on findings project_id and fingerprint

Revision ID: 5bdbb3d6f2dc
Revises: 8e5b30b42980
Create Date: 2026-09-11 09:30:17.336949

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '5bdbb3d6f2dc'
down_revision: Union[str, Sequence[str], None] = '8e5b30b42980'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_unique_constraint(
        "uq_findings_project_fingerprint",
        "findings",
        ["project_id", "fingerprint"],
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_constraint(
        "uq_findings_project_fingerprint",
        "findings",
        type_="unique",
    )
