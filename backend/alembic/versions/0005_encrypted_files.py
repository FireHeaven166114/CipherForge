"""Encrypted file sharing: encrypted files and their share links.

Adds two new tables and touches nothing that already exists. A share references its file with
``ON DELETE CASCADE``: deleting a file removes every link to it.

The ciphertext itself is stored outside the database. Downgrading drops these tables, which
orphans any ciphertext on disk; the stored data keys are gone with the rows, so that ciphertext
can no longer be opened.

Revision ID: 0005_encrypted_files
Revises: 0004_network_monitoring
Create Date: 2025-01-05 00:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005_encrypted_files"
down_revision: str | None = "0004_network_monitoring"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

PASSWORD_COLUMNS = (
    "kdf_algorithm",
    "kdf_salt",
    "kdf_time_cost",
    "kdf_memory_kib",
    "kdf_parallelism",
    "password_wrapped_dek",
)


def _timestamp() -> sa.DateTime:
    return sa.DateTime(timezone=True)


def _all_or_none(columns: tuple[str, ...]) -> str:
    all_null = " AND ".join(f"{column} IS NULL" for column in columns)
    all_set = " AND ".join(f"{column} IS NOT NULL" for column in columns)
    return f"({all_null}) OR ({all_set})"


def upgrade() -> None:
    op.create_table(
        "encrypted_files",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("owner", sa.String(length=256), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("storage_name", sa.String(length=64), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("algorithm", sa.String(length=16), nullable=False),
        sa.Column("nonce", sa.LargeBinary(length=12), nullable=False),
        sa.Column("wrapped_dek", sa.LargeBinary(), nullable=False),
        sa.Column("key_id", sa.String(length=32), nullable=False),
        sa.Column("name_nonce", sa.LargeBinary(length=12), nullable=False),
        sa.Column("name_ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", _timestamp(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_encrypted_files")),
        sa.UniqueConstraint("storage_name", name=op.f("uq_encrypted_files_storage_name")),
        sa.CheckConstraint(
            "status IN ('active', 'corrupt')", name=op.f("ck_encrypted_files_status")
        ),
        sa.CheckConstraint("algorithm = 'AES-256-GCM'", name=op.f("ck_encrypted_files_algorithm")),
        sa.CheckConstraint("size_bytes >= 0", name=op.f("ck_encrypted_files_size_non_negative")),
    )
    op.create_index(
        op.f("ix_encrypted_files_owner_created"), "encrypted_files", ["owner", "created_at"]
    )

    op.create_table(
        "file_shares",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("file_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", _timestamp(), nullable=False),
        sa.Column("expires_at", _timestamp(), nullable=False),
        sa.Column("max_downloads", sa.Integer(), nullable=False),
        sa.Column("download_count", sa.Integer(), nullable=False),
        sa.Column("last_downloaded_at", _timestamp(), nullable=True),
        sa.Column("revoked_at", _timestamp(), nullable=True),
        sa.Column("kdf_algorithm", sa.String(length=16), nullable=True),
        sa.Column("kdf_salt", sa.LargeBinary(), nullable=True),
        sa.Column("kdf_time_cost", sa.Integer(), nullable=True),
        sa.Column("kdf_memory_kib", sa.Integer(), nullable=True),
        sa.Column("kdf_parallelism", sa.Integer(), nullable=True),
        sa.Column("password_wrapped_dek", sa.LargeBinary(), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_file_shares")),
        sa.ForeignKeyConstraint(
            ["file_id"],
            ["encrypted_files.id"],
            name=op.f("fk_file_shares_file_id_encrypted_files"),
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("token_hash", name=op.f("uq_file_shares_token_hash")),
        sa.CheckConstraint(
            "expires_at > created_at", name=op.f("ck_file_shares_expires_after_created")
        ),
        sa.CheckConstraint(
            "max_downloads >= 1", name=op.f("ck_file_shares_max_downloads_positive")
        ),
        sa.CheckConstraint(
            "download_count >= 0 AND download_count <= max_downloads",
            name=op.f("ck_file_shares_download_count_range"),
        ),
        sa.CheckConstraint(
            "kdf_algorithm IS NULL OR kdf_algorithm = 'argon2id'",
            name=op.f("ck_file_shares_kdf_algorithm"),
        ),
        sa.CheckConstraint(
            _all_or_none(PASSWORD_COLUMNS), name=op.f("ck_file_shares_password_columns_consistent")
        ),
    )
    op.create_index(op.f("ix_file_shares_file_created"), "file_shares", ["file_id", "created_at"])


def downgrade() -> None:
    op.drop_table("file_shares")
    op.drop_table("encrypted_files")
