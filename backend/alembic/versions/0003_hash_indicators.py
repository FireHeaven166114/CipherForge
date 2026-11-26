"""MD5 and SHA-1 file hashes as indicator types.

Widens the ``indicator_type`` CHECK on ``threat_indicators``. SQLite cannot alter a constraint in
place, so batch mode rebuilds the table there; PostgreSQL alters the constraint directly. Existing
rows are all of a type the wider list still allows, so nothing is rewritten or lost.

Downgrading is refused while MD5 or SHA-1 indicators are stored, because the narrower constraint
could not hold them and deleting an analyst's records silently is worse than stopping.

Revision ID: 0003_hash_indicators
Revises: 0002_threat_intel
Create Date: 2025-01-03 00:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_hash_indicators"
down_revision: str | None = "0002_threat_intel"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

CONSTRAINT = "ck_threat_indicators_indicator_type"
BEFORE = "indicator_type IN ('ipv4', 'ipv6', 'domain', 'url', 'sha256')"
AFTER = "indicator_type IN ('ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256')"


def _refuse_if_foreign_keys_are_enforced() -> None:
    """Rebuilding a SQLite table drops it, and with enforcement on that cascades to its children."""
    context = op.get_context()
    if context.dialect.name != "sqlite" or context.as_sql:
        return
    if op.get_bind().exec_driver_sql("PRAGMA foreign_keys").scalar() == 1:
        raise RuntimeError(
            "SQLite foreign key enforcement is on, so rebuilding threat_indicators would delete "
            "its provider observations. Run the migration on a connection without "
            "PRAGMA foreign_keys=ON (the alembic command line does)."
        )


def _swap_constraint(condition: str) -> None:
    _refuse_if_foreign_keys_are_enforced()
    with op.batch_alter_table("threat_indicators") as batch:
        batch.drop_constraint(op.f(CONSTRAINT), type_="check")
        batch.create_check_constraint(op.f(CONSTRAINT), condition)


def upgrade() -> None:
    _swap_constraint(AFTER)


def downgrade() -> None:
    if not op.get_context().as_sql:
        stored = (
            op.get_bind()
            .execute(
                sa.text(
                    "SELECT COUNT(*) FROM threat_indicators WHERE indicator_type IN ('md5', 'sha1')"
                )
            )
            .scalar_one()
        )
        if stored:
            raise RuntimeError(
                f"Cannot downgrade: {stored} MD5 or SHA-1 indicator(s) are stored. Delete them "
                "first, or stay on this revision."
            )
    _swap_constraint(BEFORE)
