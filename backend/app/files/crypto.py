"""Envelope encryption for shared files.

Key hierarchy (every arrow is AES-256-GCM, every ciphertext is bound to its row by AAD)::

    master key (CIPHERFORGE_MASTER_KEY, 32 random bytes, never stored in the database)
      |-- wraps --> per-file data key (DEK, random 256 bit, one per file)
      |                |-- encrypts --> the file content (one-shot, tag verified before any use)
      |                '-- encrypts --> the original filename (own random nonce)
      '-- mixed into --> the key-encryption key of a password-protected share (see below)

Password-protected shares add a second way to open the same DEK::

    pw_key = Argon2id(NFKC(password), random salt, time/memory/lanes stored per share)
    kek    = HKDF-SHA256(ikm = pw_key || master key, info = "...|" + share id)
    password_wrapped_dek = AES-256-GCM(kek, DEK, aad = share id || file id)

The master key is part of the KEK on purpose: a database dump alone never allows an offline
password search, and a password share is never weaker than the at-rest protection of the file.
No password or password hash is stored; a wrong password just fails AEAD authentication, which
is constant time and says nothing about which input was wrong.

Everything here uses ``cryptography`` primitives only. Nothing in this module logs, and no
exception message contains key material, passwords or plaintext.
"""

import hashlib
import hmac
import os
import re
import secrets
import threading
import unicodedata
import uuid
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ALGORITHM = "AES-256-GCM"
KDF_ALGORITHM = "argon2id"

KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16
WRAPPED_KEY_SIZE = NONCE_SIZE + KEY_SIZE + TAG_SIZE
KEY_ID_LENGTH = 16

SALT_SIZE = 16
MIN_STORED_SALT_SIZE = 8
MAX_STORED_SALT_SIZE = 64

MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128

TOKEN_BYTES = 32
TOKEN_LENGTH = 43

_FILE_AAD = b"cipherforge/file/v1|"
_DEK_AAD = b"cipherforge/dek/v1|"
_NAME_AAD = b"cipherforge/name/v1|"
_SHARE_DEK_AAD = b"cipherforge/share-dek/v1|"
_KEY_ID_LABEL = b"cipherforge-key-id-v1"
_SHARE_KEK_INFO = b"cipherforge-share-kek-v1|"

_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}")

# Argon2id cost limits. Anything read back from the database outside them is refused, so a
# tampered row cannot make the server allocate gigabytes or spin for minutes.
MAX_KDF_TIME_COST = 10
MAX_KDF_MEMORY_KIB = 262_144
MAX_KDF_PARALLELISM = 8

# At most this many Argon2id evaluations run at once in the whole process (each one allocates
# `memory_kib` of RAM); further requests wait up to KDF_WAIT_SECONDS and are then turned away.
MAX_CONCURRENT_KDF = 2
KDF_WAIT_SECONDS = 10.0
_kdf_slots = threading.BoundedSemaphore(MAX_CONCURRENT_KDF)


class CryptoError(Exception):
    """Base class. Messages are fixed strings: no input, key or plaintext is ever included."""


class AuthenticationFailed(CryptoError):
    """An AEAD tag did not verify: the data was altered, swapped between rows or truncated."""


class WrongMasterKey(CryptoError):
    """The stored key fingerprint differs from the configured master key's fingerprint."""


class WrongPassword(CryptoError):
    """The share's password-wrapped key did not open with the supplied password."""


class InvalidKdfParameters(CryptoError):
    """Argon2id parameters or salt outside the accepted bounds (never trust stored values)."""


class KdfBusy(CryptoError):
    """All Argon2id slots stayed busy for too long."""


@dataclass(frozen=True, slots=True)
class KdfParams:
    """Argon2id cost. Stored with each password-protected share so the defaults can change."""

    time_cost: int
    memory_kib: int
    parallelism: int

    def __post_init__(self) -> None:
        values = (self.time_cost, self.memory_kib, self.parallelism)
        if not all(isinstance(value, int) and not isinstance(value, bool) for value in values):
            raise InvalidKdfParameters("KDF parameters must be integers.")
        if not 1 <= self.time_cost <= MAX_KDF_TIME_COST:
            raise InvalidKdfParameters("KDF time cost is out of range.")
        if not 1 <= self.parallelism <= MAX_KDF_PARALLELISM:
            raise InvalidKdfParameters("KDF parallelism is out of range.")
        if not 8 * self.parallelism <= self.memory_kib <= MAX_KDF_MEMORY_KIB:
            raise InvalidKdfParameters("KDF memory cost is out of range.")


# RFC 9106 recommends t=1, m=2 GiB first and t=3, m=64 MiB as the memory-constrained choice;
# the latter keeps one evaluation near 0.2 s and 64 MiB, which suits a small API server.
DEFAULT_KDF_PARAMS = KdfParams(time_cost=3, memory_kib=65_536, parallelism=1)


@dataclass(frozen=True, slots=True)
class SealedFile:
    """Everything stored for a new file. The plaintext DEK is not part of it."""

    nonce: bytes
    ciphertext: bytes
    wrapped_dek: bytes
    key_id: str
    name_nonce: bytes
    name_ciphertext: bytes


@dataclass(frozen=True, slots=True)
class PasswordWrap:
    salt: bytes
    params: KdfParams
    wrapped_dek: bytes


def _require_key(key: bytes, what: str) -> None:
    if not isinstance(key, bytes | bytearray) or len(key) != KEY_SIZE:
        raise ValueError(f"{what} must be exactly {KEY_SIZE} bytes")


def _file_aad(file_id: uuid.UUID) -> bytes:
    return _FILE_AAD + file_id.bytes


def _name_aad(file_id: uuid.UUID) -> bytes:
    return _NAME_AAD + file_id.bytes


def _dek_aad(file_id: uuid.UUID) -> bytes:
    return _DEK_AAD + file_id.bytes


def _share_dek_aad(share_id: uuid.UUID, file_id: uuid.UUID) -> bytes:
    return _SHARE_DEK_AAD + share_id.bytes + file_id.bytes


def _aead_encrypt(key: bytes, plaintext: bytes | bytearray, aad: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(NONCE_SIZE)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, aad)


def _aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    if len(nonce) != NONCE_SIZE or len(ciphertext) < TAG_SIZE:
        raise AuthenticationFailed("Ciphertext is malformed.")
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        raise AuthenticationFailed("Ciphertext failed authentication.") from None


def key_fingerprint(master_key: bytes) -> str:
    """A non-secret identifier of the master key (an HMAC under the key itself)."""
    _require_key(master_key, "master key")
    return hmac.new(master_key, _KEY_ID_LABEL, hashlib.sha256).hexdigest()[:KEY_ID_LENGTH]


def check_key_id(master_key: bytes, key_id: str) -> None:
    """Raise WrongMasterKey unless ``key_id`` is this master key's fingerprint."""
    expected = key_fingerprint(master_key).encode("ascii")
    if not hmac.compare_digest(expected, str(key_id).encode("utf-8", "replace")):
        raise WrongMasterKey("The stored data was encrypted with a different master key.")


def generate_dek() -> bytes:
    return secrets.token_bytes(KEY_SIZE)


def wrap_dek(master_key: bytes, file_id: uuid.UUID, dek: bytes) -> bytes:
    _require_key(master_key, "master key")
    nonce, ciphertext = _aead_encrypt(master_key, dek, _dek_aad(file_id))
    return nonce + ciphertext


def unwrap_dek(master_key: bytes, file_id: uuid.UUID, wrapped_dek: bytes) -> bytes:
    _require_key(master_key, "master key")
    if len(wrapped_dek) != WRAPPED_KEY_SIZE:
        raise AuthenticationFailed("Wrapped key is malformed.")
    return _aead_decrypt(
        master_key, wrapped_dek[:NONCE_SIZE], wrapped_dek[NONCE_SIZE:], _dek_aad(file_id)
    )


def seal_file(
    master_key: bytes, file_id: uuid.UUID, content: bytes | bytearray, name: str
) -> SealedFile:
    """Encrypt ``content`` and ``name`` under a fresh data key, and wrap that key.

    ``file_id`` must be generated before this call: it is bound into every ciphertext, so a blob
    cannot be moved to another row. Empty content is valid at this layer.
    """
    _require_key(master_key, "master key")
    dek = generate_dek()
    nonce, ciphertext = _aead_encrypt(dek, content, _file_aad(file_id))
    # Two messages must never share a (key, nonce) pair; 96-bit random nonces make a repeat
    # astronomically unlikely, and this loop makes it impossible.
    name_nonce, name_ciphertext = _aead_encrypt(dek, name.encode("utf-8"), _name_aad(file_id))
    while name_nonce == nonce:
        name_nonce, name_ciphertext = _aead_encrypt(dek, name.encode("utf-8"), _name_aad(file_id))
    return SealedFile(
        nonce=nonce,
        ciphertext=ciphertext,
        wrapped_dek=wrap_dek(master_key, file_id, dek),
        key_id=key_fingerprint(master_key),
        name_nonce=name_nonce,
        name_ciphertext=name_ciphertext,
    )


def open_file_dek(master_key: bytes, file_id: uuid.UUID, key_id: str, wrapped_dek: bytes) -> bytes:
    """The data key of a stored file, after checking the master-key fingerprint.

    Raises WrongMasterKey when the fingerprint differs (a configuration problem, not damage) and
    AuthenticationFailed when the wrapped key itself was altered.
    """
    check_key_id(master_key, key_id)
    return unwrap_dek(master_key, file_id, wrapped_dek)


def decrypt_content(dek: bytes, file_id: uuid.UUID, nonce: bytes, ciphertext: bytes) -> bytes:
    """Decrypt and authenticate the whole file; nothing is returned unless the tag verifies."""
    return _aead_decrypt(dek, nonce, ciphertext, _file_aad(file_id))


def decrypt_name(dek: bytes, file_id: uuid.UUID, nonce: bytes, ciphertext: bytes) -> str:
    return _aead_decrypt(dek, nonce, ciphertext, _name_aad(file_id)).decode("utf-8")


def normalize_password(password: str) -> bytes:
    """NFKC-normalised UTF-8, so visually identical passwords derive the same key.

    Raises ValueError for text that cannot be encoded (lone surrogates).
    """
    return unicodedata.normalize("NFKC", password).encode("utf-8")


def _derive_share_kek(
    master_key: bytes,
    share_id: uuid.UUID,
    secret: bytes,
    salt: bytes,
    params: KdfParams,
) -> bytes:
    _require_key(master_key, "master key")
    if not MIN_STORED_SALT_SIZE <= len(salt) <= MAX_STORED_SALT_SIZE:
        raise InvalidKdfParameters("KDF salt has an unsupported length.")
    if not _kdf_slots.acquire(timeout=KDF_WAIT_SECONDS):
        raise KdfBusy("Too many password derivations are running.")
    try:
        pw_key = Argon2id(
            salt=salt,
            length=KEY_SIZE,
            iterations=params.time_cost,
            lanes=params.parallelism,
            memory_cost=params.memory_kib,
        ).derive(secret)
    finally:
        _kdf_slots.release()
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=None,
        info=_SHARE_KEK_INFO + share_id.bytes,
    ).derive(pw_key + master_key)


def wrap_dek_for_password(
    master_key: bytes,
    share_id: uuid.UUID,
    file_id: uuid.UUID,
    dek: bytes,
    password: str,
    params: KdfParams = DEFAULT_KDF_PARAMS,
) -> PasswordWrap:
    salt = os.urandom(SALT_SIZE)
    kek = _derive_share_kek(master_key, share_id, normalize_password(password), salt, params)
    nonce, ciphertext = _aead_encrypt(kek, dek, _share_dek_aad(share_id, file_id))
    return PasswordWrap(salt=salt, params=params, wrapped_dek=nonce + ciphertext)


def unwrap_dek_with_password(
    master_key: bytes,
    share_id: uuid.UUID,
    file_id: uuid.UUID,
    password: str,
    *,
    salt: bytes,
    params: KdfParams,
    wrapped_dek: bytes,
) -> bytes:
    """Open the DEK of a password-protected share.

    ``params`` must already have been validated (constructing KdfParams does that). Raises
    WrongPassword for any failure to open the key; the caller cannot tell a wrong password from
    a damaged wrapped key, and neither can an attacker.
    """
    if len(wrapped_dek) != WRAPPED_KEY_SIZE:
        raise InvalidKdfParameters("Wrapped key is malformed.")
    try:
        secret = normalize_password(password)
    except ValueError:
        # Text that cannot be UTF-8 encoded can never have been set as a password.
        raise WrongPassword("The password is not correct.") from None
    kek = _derive_share_kek(master_key, share_id, secret, salt, params)
    try:
        return _aead_decrypt(
            kek,
            wrapped_dek[:NONCE_SIZE],
            wrapped_dek[NONCE_SIZE:],
            _share_dek_aad(share_id, file_id),
        )
    except AuthenticationFailed:
        raise WrongPassword("The password is not correct.") from None


def new_share_token() -> str:
    """A 256-bit URL-safe token: 43 characters from ``A-Za-z0-9_-``."""
    return secrets.token_urlsafe(TOKEN_BYTES)


def is_well_formed_token(value: str) -> bool:
    """Cheap shape check, done before any database access."""
    return _TOKEN_PATTERN.fullmatch(value) is not None


def hash_share_token(token: str) -> str:
    """The only form of a token that is ever stored: hex SHA-256 (the token has 256 bits)."""
    return hashlib.sha256(token.encode("ascii")).hexdigest()
