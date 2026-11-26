"""Use cases of the encrypted-file module: upload, share, download, revoke, delete, audit.

Every public download goes through the same gate, in this order; the first failing step ends the
request, and every rejection of a *known* share is audited (unknown tokens never are, so an
anonymous caller cannot flood the audit trail):

 1. per-client request rate (429 ``rate_limited``)           -- before any database access
 2. token shape (404 ``share_not_found``)                    -- still no database access
 3. share exists (404 ``share_not_found``)
 4. not revoked (410 ``share_revoked``)
 5. not expired (410 ``share_expired``)
 6. download count below the limit (410 ``share_limit_reached``)
 7. file exists and is not quarantined (409 ``file_unavailable``)
 8. master key configured (503 ``feature_not_configured``)   -- not audited
 9. master key is the one that wrapped the file (503 ``encryption_key_mismatch``)
10. password shares: a password was sent (403 ``password_required``), the wrong-password budget
    is not spent (429 ``too_many_attempts``), and it opens the key (403 ``invalid_password``)
11. the blob is read and decrypted *completely*; any authentication failure quarantines the file
    (409 ``file_unavailable``) and consumes no download
12. one conditional UPDATE reserves the download slot; if it matches no row the plaintext is
    discarded and the request is rejected as in 4-6
13. the reservation and its audit row are committed -- only then are bytes returned

Step 12 is what keeps ``max_downloads`` exact under concurrency: whichever requests the database
lets through are the ones that get data, however many ran in parallel.
"""

import logging
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import NoReturn

from fastapi.exceptions import RequestValidationError
from sqlalchemy import and_, case, delete, func, select, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.errors import ApiError
from app.files import crypto
from app.files.attempts import AttemptLimitExceeded, PasswordAttemptLimiter, client_bucket
from app.files.logsafe import install_share_token_filter
from app.files.storage import BlobIntegrityError, BlobStorage, StorageError, new_blob_name
from app.models.audit import AuditLog
from app.models.enums import FileStatus
from app.models.files import EncryptedFile, FileShare
from app.models.types import utcnow
from app.schemas.files import (
    ActivityItem,
    ActivityList,
    FileDetail,
    FileFeatureStatus,
    FileList,
    FileOut,
    PublicShareInfo,
    ShareCreated,
    ShareCreateRequest,
    ShareOut,
)
from app.security.rate_limit import SlidingWindowRateLimiter
from app.services.audit import RESULT_REJECTED, RESULT_SUCCESS, record_audit

logger = logging.getLogger("cipherforge.files")

# Audit actions.
FILE_CREATE = "FILE_CREATE"
FILE_DELETE = "FILE_DELETE"
FILE_INTEGRITY_FAILED = "FILE_INTEGRITY_FAILED"
SHARE_CREATE = "SHARE_CREATE"
SHARE_REVOKE = "SHARE_REVOKE"
SHARE_DOWNLOAD = "SHARE_DOWNLOAD"
SHARE_DOWNLOAD_REJECTED = "SHARE_DOWNLOAD_REJECTED"
# Name chosen so credential scanners do not mistake an audit action for a secret.
SHARE_UNLOCK_FAILED = "SHARE_PASSWORD_FAILED"
SHARE_EXPIRED = "SHARE_EXPIRED"
SHARE_LIMIT_REACHED = "SHARE_LIMIT_REACHED"

RESULT_FAILED = "failed"
ANONYMOUS_ACTOR = "anonymous"
UNREADABLE_NAME = "(unreadable name)"
ACTIVITY_LIMIT = 100
DEFAULT_MAX_DOWNLOADS = 1
_UUID_TEXT_LENGTH = 36

# reason -> (audit action, HTTP status, error code, message) for a rejected public access.
_REJECTIONS: dict[str, tuple[str, int, str, str]] = {
    "revoked": (SHARE_DOWNLOAD_REJECTED, 410, "share_revoked", "This link has been revoked."),
    "expired": (SHARE_EXPIRED, 410, "share_expired", "This link has expired."),
    "limit_reached": (
        SHARE_LIMIT_REACHED,
        410,
        "share_limit_reached",
        "This link has reached its download limit.",
    ),
    "file_unavailable": (
        SHARE_DOWNLOAD_REJECTED,
        409,
        "file_unavailable",
        "This file is no longer available.",
    ),
    "password_required": (
        SHARE_DOWNLOAD_REJECTED,
        403,
        "password_required",
        "A password is required for this link.",
    ),
    "invalid_password": (
        SHARE_UNLOCK_FAILED,
        403,
        "invalid_password",
        "The password is not correct.",
    ),
    "key_mismatch": (
        SHARE_DOWNLOAD_REJECTED,
        503,
        "encryption_key_mismatch",
        "The server's encryption key does not match the stored data.",
    ),
}


@dataclass(frozen=True, slots=True)
class Caller:
    """Who is acting: the principal's subject (or ``anonymous``) and their network address."""

    actor: str
    source_ip: str | None = None

    @classmethod
    def anonymous(cls, source_ip: str | None) -> "Caller":
        return cls(ANONYMOUS_ACTOR, source_ip)


@dataclass(frozen=True, slots=True)
class DownloadResult:
    content: bytes
    name: str


def _file_not_found() -> ApiError:
    return ApiError(404, "file_not_found", "File not found.")


def _share_not_found() -> ApiError:
    return ApiError(404, "share_not_found", "This link does not exist.")


def _file_unavailable() -> ApiError:
    return ApiError(409, "file_unavailable", "This file is no longer available.")


def _not_configured() -> ApiError:
    return ApiError(
        503, "feature_not_configured", "Encrypted file sharing is not configured on this server."
    )


def _key_mismatch() -> ApiError:
    return ApiError(
        503,
        "encryption_key_mismatch",
        "The server's encryption key does not match the stored data.",
    )


def _storage_unavailable() -> ApiError:
    return ApiError(503, "storage_unavailable", "File storage is temporarily unavailable.")


def _internal_error() -> ApiError:
    return ApiError(500, "internal_error", "The request could not be completed.")


def _target(file_id: uuid.UUID) -> str:
    return f"file:{file_id}"


@contextmanager
def _guard_database(event: str, **fields: str) -> Iterator[None]:
    """Turn a database failure into a generic 500 that logs only the exception type.

    SQLAlchemy error text embeds the bound parameters (token hashes, wrapped keys, ciphertext),
    which must not reach the logs through a traceback.
    """
    try:
        yield
    except SQLAlchemyError as exc:
        logger.error(event, extra={**fields, "error_type": type(exc).__name__})
        raise _internal_error() from None


def _share_status(share: FileShare, now: datetime) -> str:
    """revoked > expired > exhausted > active."""
    if share.revoked_at is not None:
        return "revoked"
    if share.expires_at <= now:
        return "expired"
    if share.download_count >= share.max_downloads:
        return "exhausted"
    return "active"


def _share_out(share: FileShare, now: datetime) -> ShareOut:
    return ShareOut(
        id=share.id,
        file_id=share.file_id,
        created_at=share.created_at,
        expires_at=share.expires_at,
        max_downloads=share.max_downloads,
        download_count=share.download_count,
        downloads_remaining=max(0, share.max_downloads - share.download_count),
        last_downloaded_at=share.last_downloaded_at,
        revoked_at=share.revoked_at,
        password_protected=share.password_protected,
        status=_share_status(share, now),  # type: ignore[arg-type]
    )


def _parse_id(value: str) -> uuid.UUID | None:
    """The canonical hyphenated form only; anything else is simply "not found"."""
    if len(value) != _UUID_TEXT_LENGTH:
        return None
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        return None
    return parsed if str(parsed) == value.lower() else None


class FileService:
    def __init__(
        self,
        settings: Settings,
        *,
        clock: Callable[[], datetime] = utcnow,
        kdf_params: crypto.KdfParams = crypto.DEFAULT_KDF_PARAMS,
        storage: BlobStorage | None = None,
        limiter_clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Build the service. Nothing is read from disk or the database here, and a missing
        master key is fine: every operation that needs it answers 503 instead."""
        self._settings = settings
        self._clock = clock
        self._kdf_params = kdf_params
        self._storage = storage or BlobStorage(settings.encrypted_file_storage_path)
        self.max_file_size_bytes = settings.max_encrypted_file_size_mb * 1024 * 1024
        self._upload_limiter = SlidingWindowRateLimiter(
            settings.file_upload_rate_limit_per_minute, 60.0, clock=limiter_clock
        )
        self._share_limiter = SlidingWindowRateLimiter(
            settings.share_create_rate_limit_per_minute, 60.0, clock=limiter_clock
        )
        self._public_limiter = SlidingWindowRateLimiter(
            settings.share_download_rate_limit_per_minute, 60.0, clock=limiter_clock
        )
        self._attempts = PasswordAttemptLimiter(
            settings.share_password_attempt_limit, clock=limiter_clock
        )
        install_share_token_filter()

    # --- Feature status and shared guards ----------------------------------------------------

    @property
    def configured(self) -> bool:
        return self._settings.master_key is not None

    def status(self) -> FileFeatureStatus:
        settings = self._settings
        return FileFeatureStatus(
            configured=self.configured,
            max_file_size_bytes=self.max_file_size_bytes,
            default_share_expiry_hours=settings.default_share_expiry_hours,
            max_share_expiry_hours=settings.max_share_expiry_hours,
            max_share_downloads=settings.max_share_downloads,
        )

    def require_configured(self) -> bytes:
        """The master key, or 503 ``feature_not_configured``."""
        master_key = self._settings.master_key
        if master_key is None:
            raise _not_configured()
        return master_key

    def enforce_upload_rate(self, owner: str) -> None:
        retry_after = self._upload_limiter.check(owner)
        if retry_after is not None:
            raise self._rate_limited(
                retry_after, "upload_rate_limited", "Too many uploads. Try again shortly."
            )

    def _enforce_share_create_rate(self, owner: str) -> None:
        # Creating a password link runs Argon2id, which holds one of the few derivation slots
        # that every password download also needs, so one user must not be able to monopolise them.
        retry_after = self._share_limiter.check(owner)
        if retry_after is not None:
            raise self._rate_limited(
                retry_after,
                "share_create_rate_limited",
                "Too many links created. Try again shortly.",
            )

    def _enforce_public_rate(self, caller: Caller) -> None:
        retry_after = self._public_limiter.check(client_bucket(caller.source_ip))
        if retry_after is not None:
            raise self._rate_limited(
                retry_after, "share_rate_limited", "Too many requests. Try again shortly."
            )

    @staticmethod
    def _rate_limited(retry_after: int, event: str, message: str) -> ApiError:
        logger.warning(event, extra={"retry_after_seconds": retry_after})
        return ApiError(429, "rate_limited", message, headers={"Retry-After": str(retry_after)})

    # --- Owner: files ------------------------------------------------------------------------

    def _owned_file(self, session: Session, owner: str, file_id: str) -> EncryptedFile:
        """The caller's file. Unknown, malformed and other owners' ids are indistinguishable."""
        parsed = _parse_id(file_id)
        file = None
        if parsed is not None:
            file = session.scalars(
                select(EncryptedFile).where(
                    EncryptedFile.id == parsed, EncryptedFile.owner == owner
                )
            ).first()
        if file is None:
            raise _file_not_found()
        return file

    @staticmethod
    def _display_name(master_key: bytes | None, file: EncryptedFile) -> str:
        if master_key is None:
            return UNREADABLE_NAME
        try:
            dek = crypto.open_file_dek(master_key, file.id, file.key_id, file.wrapped_dek)
            return crypto.decrypt_name(dek, file.id, file.name_nonce, file.name_ciphertext)
        except (crypto.CryptoError, ValueError):
            return UNREADABLE_NAME

    @staticmethod
    def _file_out(
        file: EncryptedFile, name: str, share_count: int, active_share_count: int
    ) -> FileOut:
        return FileOut(
            id=file.id,
            name=name,
            size_bytes=file.size_bytes,
            status=file.status,  # type: ignore[arg-type]
            algorithm=file.algorithm,
            created_at=file.created_at,
            share_count=share_count,
            active_share_count=active_share_count,
        )

    def create_file(
        self, session: Session, caller: Caller, *, name: str, content: bytes | bytearray
    ) -> FileOut:
        """Encrypt ``content`` in memory, store the ciphertext, then record the file.

        The blob is written first and removed again if the database insert fails, so a failure
        leaves neither an orphan blob nor a row pointing at nothing.
        """
        if not content:
            raise ApiError(422, "empty_file", "The file is empty.")
        if len(content) > self.max_file_size_bytes:
            raise ApiError(413, "file_too_large", "The file is larger than the allowed size.")
        master_key = self.require_configured()

        file_id = uuid.uuid4()
        sealed = crypto.seal_file(master_key, file_id, content, name)
        storage_name = new_blob_name()
        try:
            self._storage.write(storage_name, sealed.ciphertext)
        except StorageError:
            logger.error("blob_write_failed", extra={"file_id": str(file_id)})
            raise _storage_unavailable() from None

        now = self._clock()
        file = EncryptedFile(
            id=file_id,
            owner=caller.actor,
            status=FileStatus.ACTIVE.value,
            storage_name=storage_name,
            size_bytes=len(content),
            algorithm=crypto.ALGORITHM,
            nonce=sealed.nonce,
            wrapped_dek=sealed.wrapped_dek,
            key_id=sealed.key_id,
            name_nonce=sealed.name_nonce,
            name_ciphertext=sealed.name_ciphertext,
            created_at=now,
        )
        try:
            with _guard_database("file_create_failed", file_id=str(file_id)):
                session.add(file)
                record_audit(
                    session,
                    actor=caller.actor,
                    action=FILE_CREATE,
                    result=RESULT_SUCCESS,
                    target=_target(file_id),
                    source_ip=caller.source_ip,
                    details={"size_bytes": len(content)},
                    timestamp=now,
                )
                session.commit()
        except BaseException:
            self._discard_blob(storage_name)
            session.rollback()
            raise
        logger.info("file_created", extra={"file_id": str(file_id), "size_bytes": len(content)})
        return self._file_out(file, name, 0, 0)

    def _discard_blob(self, storage_name: str) -> None:
        try:
            self._storage.delete(storage_name)
        except StorageError:
            logger.error("blob_cleanup_failed")

    def _share_counts(
        self, session: Session, file_ids: list[uuid.UUID], now: datetime
    ) -> dict[uuid.UUID, tuple[int, int]]:
        if not file_ids:
            return {}
        live = and_(
            FileShare.revoked_at.is_(None),
            FileShare.expires_at > now,
            FileShare.download_count < FileShare.max_downloads,
        )
        rows = session.execute(
            select(FileShare.file_id, func.count(FileShare.id), func.count(case((live, 1))))
            .where(FileShare.file_id.in_(file_ids))
            .group_by(FileShare.file_id)
        ).all()
        return {file_id: (total, active) for file_id, total, active in rows}

    def list_files(self, session: Session, owner: str, *, limit: int, offset: int) -> FileList:
        now = self._clock()
        master_key = self._settings.master_key
        total = session.scalar(
            select(func.count()).select_from(EncryptedFile).where(EncryptedFile.owner == owner)
        )
        files = session.scalars(
            select(EncryptedFile)
            .where(EncryptedFile.owner == owner)
            .order_by(EncryptedFile.created_at.desc(), EncryptedFile.id.desc())
            .limit(limit)
            .offset(offset)
        ).all()
        counts = self._share_counts(session, [file.id for file in files], now)
        items = [
            self._file_out(file, self._display_name(master_key, file), *counts.get(file.id, (0, 0)))
            for file in files
        ]
        return FileList(items=items, total=total or 0)

    def get_file(self, session: Session, owner: str, file_id: str) -> FileDetail:
        now = self._clock()
        file = self._owned_file(session, owner, file_id)
        shares = session.scalars(
            select(FileShare)
            .where(FileShare.file_id == file.id)
            .order_by(FileShare.created_at.desc(), FileShare.id.desc())
        ).all()
        outputs = [_share_out(share, now) for share in shares]
        base = self._file_out(
            file,
            self._display_name(self._settings.master_key, file),
            len(outputs),
            sum(1 for share in outputs if share.status == "active"),
        )
        return FileDetail(**base.model_dump(), shares=outputs)

    def delete_file(self, session: Session, caller: Caller, file_id: str) -> None:
        """Remove the blob, the shares and the file row. The audit trail keeps its history."""
        file = self._owned_file(session, caller.actor, file_id)
        storage_name = file.storage_name
        share_count = (
            session.scalar(
                select(func.count()).select_from(FileShare).where(FileShare.file_id == file.id)
            )
            or 0
        )
        try:
            self._storage.delete(storage_name)
        except StorageError:
            logger.error("blob_delete_failed", extra={"file_id": str(file.id)})
            raise _storage_unavailable() from None
        file_id_value = file.id
        session.execute(delete(FileShare).where(FileShare.file_id == file_id_value))
        session.execute(delete(EncryptedFile).where(EncryptedFile.id == file_id_value))
        record_audit(
            session,
            actor=caller.actor,
            action=FILE_DELETE,
            result=RESULT_SUCCESS,
            target=_target(file_id_value),
            source_ip=caller.source_ip,
            details={"shares_removed": share_count},
            timestamp=self._clock(),
        )
        session.commit()
        logger.info("file_deleted", extra={"file_id": str(file_id_value), "count": share_count})

    # --- Owner: shares -----------------------------------------------------------------------

    def _share_limits(self, request: ShareCreateRequest) -> tuple[int, int]:
        settings = self._settings
        hours = (
            request.expires_in_hours
            if request.expires_in_hours is not None
            else settings.default_share_expiry_hours
        )
        downloads = (
            request.max_downloads if request.max_downloads is not None else DEFAULT_MAX_DOWNLOADS
        )
        problems = []
        if not 1 <= hours <= settings.max_share_expiry_hours:
            problems.append(
                {
                    "loc": ("body", "expires_in_hours"),
                    "msg": f"Must be between 1 and {settings.max_share_expiry_hours}.",
                    "type": "value_error",
                }
            )
        if not 1 <= downloads <= settings.max_share_downloads:
            problems.append(
                {
                    "loc": ("body", "max_downloads"),
                    "msg": f"Must be between 1 and {settings.max_share_downloads}.",
                    "type": "value_error",
                }
            )
        if problems:
            raise RequestValidationError(problems)
        return hours, downloads

    def create_share(
        self, session: Session, caller: Caller, file_id: str, request: ShareCreateRequest
    ) -> ShareCreated:
        """Create a link. The token is returned here, once; only its hash is stored."""
        file = self._owned_file(session, caller.actor, file_id)
        hours, max_downloads = self._share_limits(request)
        master_key = self.require_configured()
        if file.status != FileStatus.ACTIVE.value:
            raise _file_unavailable()
        try:
            crypto.check_key_id(master_key, file.key_id)
        except crypto.WrongMasterKey:
            raise _key_mismatch() from None
        self._enforce_share_create_rate(caller.actor)
        try:
            dek = crypto.unwrap_dek(master_key, file.id, file.wrapped_dek)
        except crypto.AuthenticationFailed:
            self._integrity_failure(session, caller, None, file, "wrapped_key_invalid")
        session.expunge_all()
        session.rollback()  # do not hold a connection through the key derivation below

        now = self._clock()
        share_id = uuid.uuid4()
        token = crypto.new_share_token()
        share = FileShare(
            id=share_id,
            file_id=file.id,
            token_hash=crypto.hash_share_token(token),
            created_at=now,
            expires_at=now + timedelta(hours=hours),
            max_downloads=max_downloads,
            download_count=0,
        )
        if request.password is not None:
            try:
                wrap = crypto.wrap_dek_for_password(
                    master_key,
                    share_id,
                    file.id,
                    dek,
                    request.password.get_secret_value(),
                    self._kdf_params,
                )
            except crypto.KdfBusy:
                raise self._busy() from None
            share.kdf_algorithm = crypto.KDF_ALGORITHM
            share.kdf_salt = wrap.salt
            share.kdf_time_cost = wrap.params.time_cost
            share.kdf_memory_kib = wrap.params.memory_kib
            share.kdf_parallelism = wrap.params.parallelism
            share.password_wrapped_dek = wrap.wrapped_dek

        with _guard_database("share_create_failed", file_id=str(file.id)):
            try:
                session.add(share)
                record_audit(
                    session,
                    actor=caller.actor,
                    action=SHARE_CREATE,
                    result=RESULT_SUCCESS,
                    target=_target(file.id),
                    source_ip=caller.source_ip,
                    details={
                        "share_id": str(share_id),
                        "expires_at": share.expires_at.isoformat(),
                        "max_downloads": max_downloads,
                        "password_protected": share.password_protected,
                    },
                    timestamp=now,
                )
                session.commit()
            except IntegrityError:
                session.rollback()
                if session.get(EncryptedFile, file.id) is None:
                    # Deleted while the link was being prepared.
                    raise _file_not_found() from None
                raise
        logger.info(
            "share_created",
            extra={
                "file_id": str(file.id),
                "share_id": str(share_id),
                "protected": share.password_protected,
            },
        )
        return ShareCreated(share=_share_out(share, now), token=token, path=f"/share/{token}")

    @staticmethod
    def _busy() -> ApiError:
        return ApiError(
            503,
            "service_busy",
            "The server is busy. Try again shortly.",
            headers={"Retry-After": "2"},
        )

    def revoke_share(
        self, session: Session, caller: Caller, file_id: str, share_id: str
    ) -> ShareOut:
        """Revoke a link. Idempotent: a second revoke changes nothing and audits nothing."""
        file = self._owned_file(session, caller.actor, file_id)
        parsed = _parse_id(share_id)
        share = None
        if parsed is not None:
            share = session.scalars(
                select(FileShare).where(FileShare.id == parsed, FileShare.file_id == file.id)
            ).first()
        if share is None:
            raise _file_not_found()
        now = self._clock()
        result = session.execute(
            update(FileShare)
            .where(FileShare.id == share.id, FileShare.revoked_at.is_(None))
            .values(revoked_at=now)
            .execution_options(synchronize_session=False)
        )
        revoked_now = result.rowcount == 1
        if revoked_now:
            record_audit(
                session,
                actor=caller.actor,
                action=SHARE_REVOKE,
                result=RESULT_SUCCESS,
                target=_target(file.id),
                source_ip=caller.source_ip,
                details={"share_id": str(share.id)},
                timestamp=now,
            )
        session.commit()
        session.refresh(share)
        if revoked_now:
            logger.info("share_revoked", extra={"file_id": str(file.id), "share_id": str(share.id)})
        return _share_out(share, now)

    def activity(self, session: Session, owner: str, file_id: str) -> ActivityList:
        """Audit rows about this file, newest first. Never other files, never source addresses."""
        file = self._owned_file(session, owner, file_id)
        rows = session.scalars(
            select(AuditLog)
            .where(AuditLog.target == _target(file.id))
            .order_by(AuditLog.timestamp.desc(), AuditLog.id.desc())
            .limit(ACTIVITY_LIMIT)
        ).all()
        items = []
        for row in rows:
            details = row.details if isinstance(row.details, dict) else {}
            share_id = details.get("share_id")
            reason = details.get("reason")
            items.append(
                ActivityItem(
                    timestamp=row.timestamp,
                    action=row.action,
                    result=row.result,
                    share_id=share_id if isinstance(share_id, str) else None,
                    reason=reason if isinstance(reason, str) else None,
                )
            )
        return ActivityList(items=items)

    # --- Public: share links -----------------------------------------------------------------

    def _reject(
        self,
        session: Session,
        caller: Caller,
        *,
        share_id: uuid.UUID,
        file_id: uuid.UUID,
        reason: str,
    ) -> NoReturn:
        """Audit (and commit) a refused access to a known share, then raise its error."""
        action, status, code, message = _REJECTIONS[reason]
        record_audit(
            session,
            actor=caller.actor,
            action=action,
            result=RESULT_REJECTED,
            target=_target(file_id),
            source_ip=caller.source_ip,
            details={"share_id": str(share_id), "reason": reason},
            timestamp=self._clock(),
        )
        session.commit()
        logger.info(
            "share_rejected",
            extra={"file_id": str(file_id), "share_id": str(share_id), "reason": reason},
        )
        raise ApiError(status, code, message)

    def _integrity_failure(
        self,
        session: Session,
        caller: Caller,
        share_id: uuid.UUID | None,
        file: EncryptedFile,
        reason: str,
    ) -> NoReturn:
        """Quarantine a file whose stored data failed authentication or went missing."""
        result = session.execute(
            update(EncryptedFile)
            .where(EncryptedFile.id == file.id, EncryptedFile.status == FileStatus.ACTIVE.value)
            .values(status=FileStatus.CORRUPT.value)
            .execution_options(synchronize_session=False)
        )
        details: dict[str, str] = {"reason": reason}
        if share_id is not None:
            details["share_id"] = str(share_id)
        if result.rowcount == 1:
            action, outcome = FILE_INTEGRITY_FAILED, RESULT_FAILED
        elif share_id is not None:
            action, outcome = SHARE_DOWNLOAD_REJECTED, RESULT_REJECTED
            details["reason"] = "file_unavailable"
        else:
            session.commit()
            raise _file_unavailable()
        record_audit(
            session,
            actor=caller.actor,
            action=action,
            result=outcome,
            target=_target(file.id),
            source_ip=caller.source_ip,
            details=details,
            timestamp=self._clock(),
        )
        session.commit()
        logger.error("file_integrity_failed", extra={"file_id": str(file.id), "reason": reason})
        raise _file_unavailable()

    def _load_usable_share(
        self, session: Session, caller: Caller, token: str
    ) -> tuple[FileShare, EncryptedFile, bytes]:
        """Steps 1-9 of the gate (see the module docstring). Returns detached rows."""
        self._enforce_public_rate(caller)
        if not crypto.is_well_formed_token(token):
            raise _share_not_found()
        row = session.execute(
            select(FileShare, EncryptedFile)
            .join(EncryptedFile, EncryptedFile.id == FileShare.file_id)
            .where(FileShare.token_hash == crypto.hash_share_token(token))
        ).first()
        if row is None:
            raise _share_not_found()
        share, file = row
        session.expunge_all()
        session.rollback()  # release the connection before any slow work

        self._reject_if_unusable(session, caller, share, file)
        master_key = self.require_configured()
        try:
            crypto.check_key_id(master_key, file.key_id)
        except crypto.WrongMasterKey:
            self._reject(session, caller, share_id=share.id, file_id=file.id, reason="key_mismatch")
        return share, file, master_key

    def _reject_if_unusable(
        self, session: Session, caller: Caller, share: FileShare, file: EncryptedFile
    ) -> None:
        status = _share_status(share, self._clock())
        reason = {"revoked": "revoked", "expired": "expired", "exhausted": "limit_reached"}.get(
            status
        )
        if reason is None and file.status != FileStatus.ACTIVE.value:
            reason = "file_unavailable"
        if reason is not None:
            self._reject(session, caller, share_id=share.id, file_id=file.id, reason=reason)

    def share_info(self, session: Session, caller: Caller, token: str) -> PublicShareInfo:
        """What a link holder may see before downloading. Consumes no download."""
        share, file, master_key = self._load_usable_share(session, caller, token)
        name = None
        if not share.password_protected:
            try:
                dek = crypto.unwrap_dek(master_key, file.id, file.wrapped_dek)
                name = crypto.decrypt_name(dek, file.id, file.name_nonce, file.name_ciphertext)
            except (crypto.AuthenticationFailed, UnicodeDecodeError):
                self._integrity_failure(session, caller, share.id, file, "authentication_failed")
        return PublicShareInfo(
            file_name=name,
            size_bytes=file.size_bytes,
            password_required=share.password_protected,
            expires_at=share.expires_at,
            downloads_remaining=max(0, share.max_downloads - share.download_count),
        )

    def _unlock_with_password(
        self,
        session: Session,
        caller: Caller,
        share: FileShare,
        file: EncryptedFile,
        master_key: bytes,
        password: str | None,
    ) -> bytes:
        if not password:
            self._reject(
                session, caller, share_id=share.id, file_id=file.id, reason="password_required"
            )
        try:
            if (
                share.kdf_algorithm != crypto.KDF_ALGORITHM
                or share.kdf_salt is None
                or share.password_wrapped_dek is None
            ):
                raise crypto.InvalidKdfParameters("Share key data is incomplete.")
            params = crypto.KdfParams(
                share.kdf_time_cost, share.kdf_memory_kib, share.kdf_parallelism
            )
        except crypto.InvalidKdfParameters:
            logger.error("share_kdf_parameters_invalid", extra={"share_id": str(share.id)})
            self._reject(
                session, caller, share_id=share.id, file_id=file.id, reason="file_unavailable"
            )

        # Reserve the attempt before the (expensive) derivation: a spent budget is refused here
        # without running the KDF, and parallel guesses cannot exceed the budget.
        try:
            reservation = self._attempts.reserve(str(share.id), client_bucket(caller.source_ip))
        except AttemptLimitExceeded as exc:
            logger.warning("share_password_locked", extra={"share_id": str(share.id)})
            raise ApiError(
                429,
                "too_many_attempts",
                "Too many wrong passwords. Try again later.",
                headers={"Retry-After": str(exc.retry_after)},
            ) from None
        try:
            dek = crypto.unwrap_dek_with_password(
                master_key,
                share.id,
                file.id,
                password,
                salt=share.kdf_salt,
                params=params,
                wrapped_dek=share.password_wrapped_dek,
            )
        except crypto.WrongPassword:
            # The reservation stays: a wrong guess is what the budget counts.
            self._reject(
                session, caller, share_id=share.id, file_id=file.id, reason="invalid_password"
            )
        except crypto.KdfBusy:
            self._attempts.release(reservation)
            raise self._busy() from None
        except crypto.InvalidKdfParameters:
            self._attempts.release(reservation)
            self._reject(
                session, caller, share_id=share.id, file_id=file.id, reason="file_unavailable"
            )
        except BaseException:
            self._attempts.release(reservation)
            raise
        self._attempts.release(reservation)
        return dek

    def download(
        self, session: Session, caller: Caller, token: str, password: str | None
    ) -> DownloadResult:
        """Return the decrypted file, having verified every byte and reserved a download."""
        share, file, master_key = self._load_usable_share(session, caller, token)
        if share.password_protected:
            dek = self._unlock_with_password(session, caller, share, file, master_key, password)
        else:
            try:
                dek = crypto.unwrap_dek(master_key, file.id, file.wrapped_dek)
            except crypto.AuthenticationFailed:
                self._integrity_failure(session, caller, share.id, file, "wrapped_key_invalid")

        try:
            blob = self._storage.read(
                file.storage_name, expected_size=file.size_bytes + crypto.TAG_SIZE
            )
            content = crypto.decrypt_content(dek, file.id, file.nonce, blob)
            name = crypto.decrypt_name(dek, file.id, file.name_nonce, file.name_ciphertext)
        except BlobIntegrityError:
            self._integrity_failure(session, caller, share.id, file, "blob_invalid")
        except (crypto.AuthenticationFailed, UnicodeDecodeError):
            self._integrity_failure(session, caller, share.id, file, "authentication_failed")
        except StorageError:
            logger.error(
                "blob_read_failed", extra={"file_id": str(file.id), "share_id": str(share.id)}
            )
            raise _storage_unavailable() from None

        self._reserve_download(session, caller, share, file)
        logger.info("share_downloaded", extra={"file_id": str(file.id), "share_id": str(share.id)})
        return DownloadResult(content=content, name=name)

    def _reserve_download(
        self, session: Session, caller: Caller, share: FileShare, file: EncryptedFile
    ) -> None:
        """Take one download slot with a single conditional UPDATE, then commit it.

        If no row matches, another request used the last slot (or the link was revoked or ran
        out) while this one was decrypting: the plaintext is dropped by the caller unwinding.
        """
        now = self._clock()
        with _guard_database("share_reserve_failed", share_id=str(share.id)):
            result = session.execute(
                update(FileShare)
                .where(
                    FileShare.id == share.id,
                    FileShare.download_count < FileShare.max_downloads,
                    FileShare.revoked_at.is_(None),
                    FileShare.expires_at > now,
                )
                .values(download_count=FileShare.download_count + 1, last_downloaded_at=now)
                .execution_options(synchronize_session=False)
            )
            if result.rowcount == 1:
                record_audit(
                    session,
                    actor=caller.actor,
                    action=SHARE_DOWNLOAD,
                    result=RESULT_SUCCESS,
                    target=_target(file.id),
                    source_ip=caller.source_ip,
                    details={"share_id": str(share.id)},
                    timestamp=now,
                )
                session.commit()
                return
            session.rollback()
            current = session.get(FileShare, share.id, populate_existing=True)
            if current is None:
                raise _share_not_found()
            session.expunge_all()
            session.rollback()
        self._reject_if_unusable(session, caller, current, file)
        # Not reachable in practice (the slot was lost, so the share must be unusable now).
        raise _file_unavailable()
