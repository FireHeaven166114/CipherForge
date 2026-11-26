"""Encrypted-file-sharing tables.

* ``encrypted_files`` - one stored ciphertext blob plus the cryptographic material needed to
  open it: the per-file key wrapped with the server master key, the nonces, and the encrypted
  original filename. No plaintext content and no plaintext filename is stored.
* ``file_shares``     - one share link. Only a SHA-256 hash of the link token is stored, so a
  database dump cannot be used to download a file.

The ciphertext itself lives outside the database (see ``app.files.storage``).
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.enums import FileStatus
from app.models.types import UTCDateTime, in_list, utcnow

# Every column that exists only for password-protected shares. They are all set together or
# all null (see the matching CHECK on FileShare).
_PASSWORD_COLUMNS = (
    "kdf_algorithm",
    "kdf_salt",
    "kdf_time_cost",
    "kdf_memory_kib",
    "kdf_parallelism",
    "password_wrapped_dek",
)


def _all_or_none(columns: tuple[str, ...]) -> str:
    all_null = " AND ".join(f"{column} IS NULL" for column in columns)
    all_set = " AND ".join(f"{column} IS NOT NULL" for column in columns)
    return f"({all_null}) OR ({all_set})"


class EncryptedFile(Base):
    __tablename__ = "encrypted_files"
    __table_args__ = (
        CheckConstraint(in_list("status", FileStatus), name="status"),
        CheckConstraint("algorithm = 'AES-256-GCM'", name="algorithm"),
        CheckConstraint("size_bytes >= 0", name="size_non_negative"),
        Index("ix_encrypted_files_owner_created", "owner", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    owner: Mapped[str] = mapped_column(String(256), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default=FileStatus.ACTIVE.value)
    # Random server-generated name of the ciphertext blob; never derived from user input.
    storage_name: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    # Plaintext size in bytes.
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    algorithm: Mapped[str] = mapped_column(String(16), nullable=False, default="AES-256-GCM")
    # 96-bit GCM nonce used for the file content.
    nonce: Mapped[bytes] = mapped_column(LargeBinary(12), nullable=False)
    # The per-file data key, encrypted with the master key (nonce || ciphertext || tag).
    wrapped_dek: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    # Non-secret fingerprint of the master key that wrapped the data key.
    key_id: Mapped[str] = mapped_column(String(32), nullable=False)
    # The original filename, encrypted under the data key with its own nonce.
    name_nonce: Mapped[bytes] = mapped_column(LargeBinary(12), nullable=False)
    name_ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)


class FileShare(Base):
    __tablename__ = "file_shares"
    __table_args__ = (
        CheckConstraint("expires_at > created_at", name="expires_after_created"),
        CheckConstraint("max_downloads >= 1", name="max_downloads_positive"),
        CheckConstraint(
            "download_count >= 0 AND download_count <= max_downloads", name="download_count_range"
        ),
        CheckConstraint(
            "kdf_algorithm IS NULL OR kdf_algorithm = 'argon2id'", name="kdf_algorithm"
        ),
        CheckConstraint(_all_or_none(_PASSWORD_COLUMNS), name="password_columns_consistent"),
        Index("ix_file_shares_file_created", "file_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    file_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("encrypted_files.id", ondelete="CASCADE"), nullable=False
    )
    # Hex SHA-256 of the 256-bit random link token. The token itself is shown once, at creation.
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    max_downloads: Mapped[int] = mapped_column(Integer, nullable=False)
    download_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_downloaded_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    # Password-protected shares only. The share's own wrapping key is derived from the password
    # (Argon2id, parameters stored here so they can change later) and the server master key.
    kdf_algorithm: Mapped[str | None] = mapped_column(String(16), nullable=True)
    kdf_salt: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    kdf_time_cost: Mapped[int | None] = mapped_column(Integer, nullable=True)
    kdf_memory_kib: Mapped[int | None] = mapped_column(Integer, nullable=True)
    kdf_parallelism: Mapped[int | None] = mapped_column(Integer, nullable=True)
    password_wrapped_dek: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    @property
    def password_protected(self) -> bool:
        return self.kdf_algorithm is not None
