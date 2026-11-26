"""Request and response models of the encrypted-file endpoints."""

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, StrictInt, field_validator

from app.files.crypto import MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH

ShareStatus = Literal["active", "expired", "revoked", "exhausted"]
FileState = Literal["active", "corrupt"]


def _encodable(value: SecretStr | None) -> SecretStr | None:
    """Reject text that cannot be UTF-8 encoded (lone surrogates) instead of crashing later."""
    if value is not None:
        try:
            value.get_secret_value().encode("utf-8")
        except UnicodeEncodeError:
            raise ValueError("must be valid Unicode text") from None
    return value


class FileFeatureStatus(BaseModel):
    configured: bool
    max_file_size_bytes: int
    default_share_expiry_hours: int
    max_share_expiry_hours: int
    max_share_downloads: int
    min_password_length: int = MIN_PASSWORD_LENGTH
    max_password_length: int = MAX_PASSWORD_LENGTH


class ShareOut(BaseModel):
    id: uuid.UUID
    file_id: uuid.UUID
    created_at: datetime
    expires_at: datetime
    max_downloads: int
    download_count: int
    downloads_remaining: int
    last_downloaded_at: datetime | None
    revoked_at: datetime | None
    password_protected: bool
    status: ShareStatus


class FileOut(BaseModel):
    id: uuid.UUID
    name: str
    size_bytes: int
    status: FileState
    algorithm: str
    created_at: datetime
    share_count: int
    active_share_count: int


class FileDetail(FileOut):
    shares: list[ShareOut]


class FileList(BaseModel):
    items: list[FileOut]
    total: int


class ShareCreateRequest(BaseModel):
    """Both limits are optional; the allowed range depends on the server's settings and is
    enforced by the service (422), the defaults being the configured expiry and one download."""

    model_config = ConfigDict(extra="forbid")

    expires_in_hours: StrictInt | None = None
    max_downloads: StrictInt | None = None
    # Optional. Absent or null means "no password"; an empty string is invalid, not "no password".
    password: SecretStr | None = Field(
        default=None, min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH
    )

    @field_validator("password")
    @classmethod
    def _password_is_text(cls, value: SecretStr | None) -> SecretStr | None:
        return _encodable(value)


class ShareCreated(BaseModel):
    share: ShareOut
    # Shown exactly once: only its SHA-256 is stored, so it cannot be shown again.
    token: str
    path: str


class ActivityItem(BaseModel):
    timestamp: datetime
    action: str
    result: str
    share_id: str | None
    reason: str | None


class ActivityList(BaseModel):
    items: list[ActivityItem]


class DownloadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    password: SecretStr | None = Field(default=None, max_length=MAX_PASSWORD_LENGTH)

    @field_validator("password")
    @classmethod
    def _password_is_text(cls, value: SecretStr | None) -> SecretStr | None:
        return _encodable(value)


class PublicShareInfo(BaseModel):
    state: Literal["available"] = "available"
    # Null when a password is required: the name is only revealed to someone who has it.
    file_name: str | None
    size_bytes: int
    password_required: bool
    expires_at: datetime
    downloads_remaining: int
