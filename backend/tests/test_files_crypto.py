"""Envelope encryption: round trips, tamper detection, key and row binding, tokens, KDF limits."""

import hashlib
import secrets
import threading
import unicodedata
import uuid

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.files import crypto
from app.files.crypto import (
    DEFAULT_KDF_PARAMS,
    AuthenticationFailed,
    InvalidKdfParameters,
    KdfBusy,
    KdfParams,
    WrongMasterKey,
    WrongPassword,
)
from tests.files_helpers import FAST_KDF

MASTER = secrets.token_bytes(32)
OTHER_MASTER = secrets.token_bytes(32)
CONTENT = b"top secret payload " * 100
NAME = "plan.txt"
PASSWORD = "correct horse staple"


def seal(content: bytes = CONTENT, *, file_id: uuid.UUID | None = None, master: bytes = MASTER):
    file_id = file_id or uuid.uuid4()
    return file_id, crypto.seal_file(master, file_id, content, NAME)


def open_dek(file_id: uuid.UUID, sealed: crypto.SealedFile, master: bytes = MASTER) -> bytes:
    return crypto.open_file_dek(master, file_id, sealed.key_id, sealed.wrapped_dek)


def flip(data: bytes, index: int, bit: int = 0) -> bytes:
    changed = bytearray(data)
    changed[index] ^= 1 << bit
    return bytes(changed)


# --- Round trip and layout ---------------------------------------------------------------------


def test_round_trip_restores_the_exact_content_and_name() -> None:
    file_id, sealed = seal()
    dek = open_dek(file_id, sealed)

    plaintext = crypto.decrypt_content(dek, file_id, sealed.nonce, sealed.ciphertext)

    assert hashlib.sha256(plaintext).digest() == hashlib.sha256(CONTENT).digest()
    assert crypto.decrypt_name(dek, file_id, sealed.name_nonce, sealed.name_ciphertext) == NAME


def test_empty_content_is_valid_at_the_crypto_layer() -> None:
    file_id, sealed = seal(b"")

    assert len(sealed.ciphertext) == crypto.TAG_SIZE
    dek = open_dek(file_id, sealed)
    assert crypto.decrypt_content(dek, file_id, sealed.nonce, sealed.ciphertext) == b""


def test_a_bytearray_is_encrypted_like_bytes() -> None:
    file_id = uuid.uuid4()
    sealed = crypto.seal_file(MASTER, file_id, bytearray(CONTENT), NAME)

    dek = open_dek(file_id, sealed)
    assert crypto.decrypt_content(dek, file_id, sealed.nonce, sealed.ciphertext) == CONTENT


def test_ciphertext_hides_the_plaintext_and_the_name() -> None:
    _, sealed = seal(b"MARKER-bytes-in-the-clear" * 8)

    assert b"MARKER" not in sealed.ciphertext
    assert NAME.encode() not in sealed.name_ciphertext
    assert len(sealed.ciphertext) == len(b"MARKER-bytes-in-the-clear" * 8) + crypto.TAG_SIZE


def test_stored_layout_follows_the_documented_design() -> None:
    """Decrypt with plain AESGCM and the documented AAD, so format drift is caught."""
    file_id, sealed = seal()

    assert len(sealed.nonce) == len(sealed.name_nonce) == crypto.NONCE_SIZE == 12
    assert len(sealed.wrapped_dek) == crypto.WRAPPED_KEY_SIZE == 60
    dek = AESGCM(MASTER).decrypt(
        sealed.wrapped_dek[:12], sealed.wrapped_dek[12:], b"cipherforge/dek/v1|" + file_id.bytes
    )
    assert len(dek) == 32
    assert (
        AESGCM(dek).decrypt(
            sealed.nonce, sealed.ciphertext, b"cipherforge/file/v1|" + file_id.bytes
        )
        == CONTENT
    )
    assert (
        AESGCM(dek).decrypt(
            sealed.name_nonce, sealed.name_ciphertext, b"cipherforge/name/v1|" + file_id.bytes
        )
        == NAME.encode()
    )


def test_key_id_is_the_documented_hmac_fingerprint() -> None:
    import hmac

    expected = hmac.new(MASTER, b"cipherforge-key-id-v1", hashlib.sha256).hexdigest()[:16]

    assert crypto.key_fingerprint(MASTER) == expected
    assert len(expected) == crypto.KEY_ID_LENGTH == 16
    assert crypto.key_fingerprint(MASTER) != crypto.key_fingerprint(OTHER_MASTER)
    assert MASTER.hex()[:16] != expected


# --- Uniqueness ---------------------------------------------------------------------------------


def test_identical_content_encrypts_differently_each_time() -> None:
    file_id = uuid.uuid4()
    first = crypto.seal_file(MASTER, file_id, CONTENT, NAME)
    second = crypto.seal_file(MASTER, file_id, CONTENT, NAME)

    assert first.nonce != second.nonce
    assert first.ciphertext != second.ciphertext
    assert first.wrapped_dek != second.wrapped_dek
    assert first.name_ciphertext != second.name_ciphertext
    assert open_dek(file_id, first) != open_dek(file_id, second)


def test_nonces_are_unique_and_never_reused_within_a_file() -> None:
    nonces: set[bytes] = set()
    for _ in range(2000):
        _, sealed = seal(b"x")
        assert sealed.nonce != sealed.name_nonce
        nonces.update((sealed.nonce, sealed.name_nonce))

    assert len(nonces) == 4000


def test_data_keys_are_random_256_bit_values() -> None:
    keys = {crypto.generate_dek() for _ in range(500)}

    assert len(keys) == 500
    assert all(len(key) == 32 for key in keys)


# --- Tampering ----------------------------------------------------------------------------------


@pytest.mark.parametrize("position", ["first", "middle", "last-data", "tag"])
def test_any_flipped_bit_in_the_ciphertext_is_detected(position: str) -> None:
    file_id, sealed = seal()
    dek = open_dek(file_id, sealed)
    index = {
        "first": 0,
        "middle": len(CONTENT) // 2,
        "last-data": len(CONTENT) - 1,
        "tag": len(sealed.ciphertext) - 1,
    }[position]

    with pytest.raises(AuthenticationFailed):
        crypto.decrypt_content(dek, file_id, sealed.nonce, flip(sealed.ciphertext, index, 3))


def test_truncated_or_extended_ciphertext_is_detected() -> None:
    file_id, sealed = seal()
    dek = open_dek(file_id, sealed)

    for damaged in (
        sealed.ciphertext[:-1],
        sealed.ciphertext[:-16],
        sealed.ciphertext + b"\x00",
        sealed.ciphertext[:8],
        b"",
    ):
        with pytest.raises(AuthenticationFailed):
            crypto.decrypt_content(dek, file_id, sealed.nonce, damaged)


def test_wrong_or_malformed_nonce_is_detected() -> None:
    file_id, sealed = seal()
    dek = open_dek(file_id, sealed)

    with pytest.raises(AuthenticationFailed):
        crypto.decrypt_content(dek, file_id, flip(sealed.nonce, 0), sealed.ciphertext)
    with pytest.raises(AuthenticationFailed):
        crypto.decrypt_content(dek, file_id, sealed.nonce[:-1], sealed.ciphertext)


def test_tampered_name_ciphertext_is_detected() -> None:
    file_id, sealed = seal()
    dek = open_dek(file_id, sealed)

    with pytest.raises(AuthenticationFailed):
        crypto.decrypt_name(dek, file_id, sealed.name_nonce, flip(sealed.name_ciphertext, 0))


def test_tampered_or_truncated_wrapped_key_is_detected() -> None:
    file_id, sealed = seal()

    for damaged in (
        flip(sealed.wrapped_dek, 0),
        flip(sealed.wrapped_dek, 30),
        flip(sealed.wrapped_dek, 59),
        sealed.wrapped_dek[:-1],
        sealed.wrapped_dek + b"\x00",
        b"",
    ):
        with pytest.raises(AuthenticationFailed):
            crypto.unwrap_dek(MASTER, file_id, damaged)


# --- Binding to rows and keys -------------------------------------------------------------------


def test_ciphertext_cannot_be_moved_to_another_file_row() -> None:
    first_id, first = seal()
    second_id, _ = seal()
    dek = open_dek(first_id, first)

    with pytest.raises(AuthenticationFailed):
        crypto.decrypt_content(dek, second_id, first.nonce, first.ciphertext)
    with pytest.raises(AuthenticationFailed):
        crypto.decrypt_name(dek, second_id, first.name_nonce, first.name_ciphertext)
    with pytest.raises(AuthenticationFailed):
        crypto.unwrap_dek(MASTER, second_id, first.wrapped_dek)


def test_swapping_every_stored_field_between_two_files_is_detected() -> None:
    first_id, first = seal(b"first file")
    second_id, second = seal(b"second file")

    # An attacker who copies file B's whole record (key, nonce, ciphertext) into A's row.
    with pytest.raises(AuthenticationFailed):
        crypto.open_file_dek(MASTER, first_id, second.key_id, second.wrapped_dek)
    # Same key id, so the wrapped key itself must be what fails to authenticate.
    assert first.key_id == second.key_id
    assert second_id != first_id


def test_a_different_master_key_is_reported_as_wrong_key_not_as_tampering() -> None:
    file_id, sealed = seal()

    with pytest.raises(WrongMasterKey):
        crypto.open_file_dek(OTHER_MASTER, file_id, sealed.key_id, sealed.wrapped_dek)
    with pytest.raises(AuthenticationFailed):
        crypto.unwrap_dek(OTHER_MASTER, file_id, sealed.wrapped_dek)


def test_a_damaged_wrapped_key_under_the_right_master_key_is_tampering() -> None:
    file_id, sealed = seal()

    with pytest.raises(AuthenticationFailed):
        crypto.open_file_dek(MASTER, file_id, sealed.key_id, flip(sealed.wrapped_dek, 20))


def test_a_stored_key_id_of_another_length_or_type_is_a_mismatch() -> None:
    file_id, sealed = seal()

    for key_id in ("", sealed.key_id[:-1], sealed.key_id + "0", "é" * 16):
        with pytest.raises(WrongMasterKey):
            crypto.open_file_dek(MASTER, file_id, key_id, sealed.wrapped_dek)


@pytest.mark.parametrize("key", [b"", b"short", b"x" * 31, b"x" * 33, "x" * 32])
def test_master_keys_must_be_exactly_32_bytes(key: bytes) -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        crypto.seal_file(key, uuid.uuid4(), b"data", NAME)
    with pytest.raises(ValueError, match="32 bytes"):
        crypto.key_fingerprint(key)


# --- Password-protected shares --------------------------------------------------------------------


def wrap(password: str = PASSWORD, *, master: bytes = MASTER):
    share_id, file_id = uuid.uuid4(), uuid.uuid4()
    dek = crypto.generate_dek()
    return (
        share_id,
        file_id,
        dek,
        crypto.wrap_dek_for_password(master, share_id, file_id, dek, password, FAST_KDF),
    )


def unwrap(share_id, file_id, wrapped, password: str = PASSWORD, *, master: bytes = MASTER):
    return crypto.unwrap_dek_with_password(
        master,
        share_id,
        file_id,
        password,
        salt=wrapped.salt,
        params=wrapped.params,
        wrapped_dek=wrapped.wrapped_dek,
    )


def test_the_right_password_opens_the_data_key() -> None:
    share_id, file_id, dek, wrapped = wrap()

    assert unwrap(share_id, file_id, wrapped) == dek
    assert wrapped.params == FAST_KDF
    assert len(wrapped.salt) == crypto.SALT_SIZE == 16


def test_a_wrong_password_fails_authentication() -> None:
    share_id, file_id, _, wrapped = wrap()

    for guess in ("", "x", PASSWORD + " ", PASSWORD.upper(), PASSWORD[:-1], "wrong password!"):
        with pytest.raises(WrongPassword):
            unwrap(share_id, file_id, wrapped, guess)


def test_password_wrapping_follows_the_documented_derivation() -> None:
    """Recompute the key-encryption key independently: Argon2id, then HKDF with the master key."""
    share_id, file_id, dek, wrapped = wrap()
    stretched = Argon2id(
        salt=wrapped.salt,
        length=32,
        iterations=FAST_KDF.time_cost,
        lanes=FAST_KDF.parallelism,
        memory_cost=FAST_KDF.memory_kib,
    ).derive(unicodedata.normalize("NFKC", PASSWORD).encode("utf-8"))
    kek = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"cipherforge-share-kek-v1|" + share_id.bytes,
    ).derive(stretched + MASTER)

    opened = AESGCM(kek).decrypt(
        wrapped.wrapped_dek[:12],
        wrapped.wrapped_dek[12:],
        b"cipherforge/share-dek/v1|" + share_id.bytes + file_id.bytes,
    )

    assert opened == dek
    assert len(wrapped.wrapped_dek) == crypto.WRAPPED_KEY_SIZE


def test_the_master_key_is_part_of_the_password_key() -> None:
    """With the right password but without the master key (a database-only attacker) nothing
    opens, so the stored values cannot be attacked offline."""
    share_id, file_id, _, wrapped = wrap()

    with pytest.raises(WrongPassword):
        unwrap(share_id, file_id, wrapped, master=OTHER_MASTER)


def test_a_password_wrap_is_bound_to_its_share_and_file() -> None:
    share_id, file_id, _, wrapped = wrap()

    with pytest.raises(WrongPassword):
        unwrap(uuid.uuid4(), file_id, wrapped)
    with pytest.raises(WrongPassword):
        unwrap(share_id, uuid.uuid4(), wrapped)


def test_every_password_wrap_has_a_fresh_salt_and_nonce() -> None:
    share_id, file_id, dek = uuid.uuid4(), uuid.uuid4(), crypto.generate_dek()
    first = crypto.wrap_dek_for_password(MASTER, share_id, file_id, dek, PASSWORD, FAST_KDF)
    second = crypto.wrap_dek_for_password(MASTER, share_id, file_id, dek, PASSWORD, FAST_KDF)

    assert first.salt != second.salt
    assert first.wrapped_dek != second.wrapped_dek


def test_visually_identical_passwords_derive_the_same_key() -> None:
    composed, decomposed = "caf\u00e9-pass-1", "cafe\u0301-pass-1"
    fullwidth = "\uff50\uff41\uff53\uff53\uff57\uff4f\uff52\uff44\uff11\uff12\uff13"
    share_id, file_id, dek, wrapped = wrap(composed)

    assert unwrap(share_id, file_id, wrapped, decomposed) == dek
    share_id, file_id, dek, wrapped = wrap("password123")
    assert unwrap(share_id, file_id, wrapped, fullwidth) == dek


def test_a_password_that_cannot_be_encoded_is_simply_wrong() -> None:
    share_id, file_id, _, wrapped = wrap()

    with pytest.raises(WrongPassword):
        unwrap(share_id, file_id, wrapped, "\ud800 lone surrogate")


def test_a_tampered_password_wrap_never_opens() -> None:
    share_id, file_id, _, wrapped = wrap()

    for damaged in (flip(wrapped.wrapped_dek, 0), flip(wrapped.wrapped_dek, 40)):
        tampered = crypto.PasswordWrap(wrapped.salt, wrapped.params, damaged)
        with pytest.raises(WrongPassword):
            unwrap(share_id, file_id, tampered)
    tampered = crypto.PasswordWrap(flip(wrapped.salt, 0), wrapped.params, wrapped.wrapped_dek)
    with pytest.raises(WrongPassword):
        unwrap(share_id, file_id, tampered)


@pytest.mark.parametrize("length", [0, 7, 65, 200])
def test_stored_salts_of_unsupported_length_are_refused(length: int) -> None:
    share_id, file_id, _, wrapped = wrap()
    tampered = crypto.PasswordWrap(b"s" * length, wrapped.params, wrapped.wrapped_dek)

    with pytest.raises(InvalidKdfParameters):
        unwrap(share_id, file_id, tampered)


def test_a_wrapped_key_of_the_wrong_size_is_refused() -> None:
    share_id, file_id, _, wrapped = wrap()

    for size in (0, 59, 61):
        tampered = crypto.PasswordWrap(wrapped.salt, wrapped.params, b"w" * size)
        with pytest.raises(InvalidKdfParameters):
            unwrap(share_id, file_id, tampered)


# --- KDF parameter limits ---------------------------------------------------------------------


def test_production_default_parameters_work_end_to_end() -> None:
    """The one test that pays for the real Argon2id cost (3 passes over 64 MiB)."""
    assert KdfParams(time_cost=3, memory_kib=65_536, parallelism=1) == DEFAULT_KDF_PARAMS
    share_id, file_id, dek = uuid.uuid4(), uuid.uuid4(), crypto.generate_dek()

    wrapped = crypto.wrap_dek_for_password(MASTER, share_id, file_id, dek, PASSWORD)

    assert wrapped.params == DEFAULT_KDF_PARAMS
    assert unwrap(share_id, file_id, wrapped) == dek
    with pytest.raises(WrongPassword):
        unwrap(share_id, file_id, wrapped, "not the password")


@pytest.mark.parametrize(
    ("time_cost", "memory_kib", "parallelism"),
    [
        (0, 64, 1),
        (11, 64, 1),
        (-1, 64, 1),
        (1, 0, 1),
        (1, 7, 1),
        (1, 262_145, 1),
        (1, 10**9, 1),
        (1, 64, 0),
        (1, 64, 9),
        (1, 63, 8),
        (1.5, 64, 1),
        (1, "64", 1),
        (None, 64, 1),
        (True, 64, 1),
    ],
)
def test_out_of_range_kdf_parameters_are_refused(
    time_cost: object, memory_kib: object, parallelism: object
) -> None:
    with pytest.raises(InvalidKdfParameters):
        KdfParams(time_cost, memory_kib, parallelism)  # type: ignore[arg-type]


@pytest.mark.parametrize("params", [(1, 8, 1), (10, 262_144, 8), (3, 65_536, 1), (1, 64, 8)])
def test_parameters_on_the_boundary_are_accepted(params: tuple[int, int, int]) -> None:
    assert KdfParams(*params).memory_kib == params[1]


def test_derivations_are_limited_to_two_at_a_time() -> None:
    assert crypto.MAX_CONCURRENT_KDF == 2
    held = [crypto._kdf_slots.acquire(blocking=False) for _ in range(3)]
    try:
        assert held == [True, True, False]
    finally:
        for acquired in held:
            if acquired:
                crypto._kdf_slots.release()


def test_a_derivation_gives_up_when_every_slot_stays_busy(monkeypatch: pytest.MonkeyPatch) -> None:
    slots = threading.BoundedSemaphore(1)
    monkeypatch.setattr(crypto, "_kdf_slots", slots)
    monkeypatch.setattr(crypto, "KDF_WAIT_SECONDS", 0.05)
    share_id, file_id, dek = uuid.uuid4(), uuid.uuid4(), crypto.generate_dek()
    assert slots.acquire(blocking=False)

    with pytest.raises(KdfBusy):
        crypto.wrap_dek_for_password(MASTER, share_id, file_id, dek, PASSWORD, FAST_KDF)

    slots.release()
    assert crypto.wrap_dek_for_password(MASTER, share_id, file_id, dek, PASSWORD, FAST_KDF)
    # The slot is given back even though the derivation succeeded.
    assert slots.acquire(blocking=False)


def test_the_slot_is_released_when_a_derivation_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    class Exploding:
        def __init__(self, **_: object) -> None:
            pass

        def derive(self, _: bytes) -> bytes:
            raise RuntimeError("derivation failed")

    slots = threading.BoundedSemaphore(1)
    monkeypatch.setattr(crypto, "_kdf_slots", slots)
    monkeypatch.setattr(crypto, "Argon2id", Exploding)

    with pytest.raises(RuntimeError, match="derivation failed"):
        crypto._derive_share_kek(MASTER, uuid.uuid4(), b"pw", b"s" * 16, FAST_KDF)
    assert slots.acquire(blocking=False)


# --- Share tokens ---------------------------------------------------------------------------------


def test_tokens_are_43_url_safe_characters_of_256_bit_entropy() -> None:
    for _ in range(200):
        token = crypto.new_share_token()
        assert len(token) == crypto.TOKEN_LENGTH == 43
        assert crypto.is_well_formed_token(token)
        assert set(token) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def test_tokens_do_not_repeat() -> None:
    assert len({crypto.new_share_token() for _ in range(5000)}) == 5000


def test_only_the_sha256_of_a_token_is_derived_for_storage() -> None:
    token = crypto.new_share_token()
    digest = crypto.hash_share_token(token)

    assert digest == hashlib.sha256(token.encode()).hexdigest()
    assert len(digest) == 64
    assert token not in digest
    assert crypto.hash_share_token(token) == digest
    assert crypto.hash_share_token(crypto.new_share_token()) != digest


@pytest.mark.parametrize(
    "value",
    [
        "",
        "a" * 42,
        "a" * 44,
        "a" * 42 + "\n",
        "a" * 42 + "=",
        "a" * 42 + "+",
        "a" * 42 + "/",
        "a" * 42 + " ",
        "a" * 42 + "é",
        "a" * 42 + "\u0661",
        "../" + "a" * 40,
        "a" * 21 + "\x00" + "a" * 21,
    ],
)
def test_malformed_tokens_are_rejected_by_shape(value: str) -> None:
    assert not crypto.is_well_formed_token(value)


def test_well_formed_tokens_include_the_url_safe_punctuation() -> None:
    assert crypto.is_well_formed_token("-" * 21 + "_" * 22)
    assert crypto.is_well_formed_token("A" * 43)


def test_crypto_errors_carry_fixed_messages_without_secrets() -> None:
    share_id, file_id, _, wrapped = wrap("a-very-unique-password")
    with pytest.raises(WrongPassword) as wrong:
        unwrap(share_id, file_id, wrapped, "another-unique-password")
    file_id, sealed = seal(b"unique-plaintext-marker")
    with pytest.raises(AuthenticationFailed) as damaged:
        crypto.decrypt_content(crypto.generate_dek(), file_id, sealed.nonce, sealed.ciphertext)

    for error in (wrong.value, damaged.value):
        text = repr(error) + str(error)
        assert "unique" not in text
        assert MASTER.hex() not in text
