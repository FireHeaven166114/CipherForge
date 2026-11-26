"""File names: header decoding, sanitising and the Content-Disposition header."""

import pytest

from app.files.names import (
    InvalidFilename,
    content_disposition,
    decode_filename_header,
    filename_from_header,
    sanitize_filename,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("report.txt", "report.txt"),
        ("My Report (final) v2.docx", "My Report (final) v2.docx"),
        ("résumé 日本語.pdf", "résumé 日本語.pdf"),
        ("../../etc/passwd", "passwd"),
        ("..\\..\\windows\\system32\\evil.dll", "evil.dll"),
        ("/absolute/path/file.txt", "file.txt"),
        ("C:\\Users\\victim\\file.txt", "file.txt"),
        ("a/b\\c/d.txt", "d.txt"),
        ("evil\x00.txt", "evil.txt"),
        ("tab\there\r\nbreak.txt", "tabherebreak.txt"),
        ("photo\u202egnp.exe", "photognp.exe"),
        ("zero\u200bwidth\u200d.txt", "zerowidth.txt"),
        ("line\u2028para\u2029.txt", "linepara.txt"),
        ("bom\ufeff.txt", "bom.txt"),
        ('a<b>c:d"e|f?g*h.txt', "a_b_c_d_e_f_g_h.txt"),
        ("  spaced name.txt  ", "spaced name.txt"),
        ("..hidden..", "hidden"),
        (".bashrc", "bashrc"),
        ("trailing dot.", "trailing dot"),
        ("e\u0301.txt", "\u00e9.txt"),
    ],
)
def test_names_are_reduced_to_a_safe_last_component(raw: str, expected: str) -> None:
    assert sanitize_filename(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        " ",
        "   ",
        ".",
        "..",
        "...",
        "/",
        "\\",
        "../",
        "..\\",
        "a/",
        "\x00",
        "\u202e",
        "\u200b .",
    ],
)
def test_names_that_are_empty_after_cleaning_are_rejected(raw: str) -> None:
    with pytest.raises(InvalidFilename):
        sanitize_filename(raw)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("CON", "_CON"),
        ("con", "_con"),
        ("con.txt", "_con.txt"),
        ("NUL.tar.gz", "_NUL.tar.gz"),
        ("Prn", "_Prn"),
        ("AUX", "_AUX"),
        ("COM1", "_COM1"),
        ("com9.log", "_com9.log"),
        ("LPT1", "_LPT1"),
        ("lpt9.txt", "_lpt9.txt"),
        ("CON.", "_CON"),
        ("aux .txt", "_aux .txt"),
        ("CONIN$", "_CONIN$"),
        ("COM\u00b9", "_COM\u00b9"),
        ("COM0", "COM0"),
        ("COM10", "COM10"),
        ("CONSOLE.txt", "CONSOLE.txt"),
        ("my-con.txt", "my-con.txt"),
        ("AUX:stream", "AUX_stream"),
    ],
)
def test_reserved_windows_device_names_are_defused(raw: str, expected: str) -> None:
    assert sanitize_filename(raw) == expected


def test_a_long_name_is_capped_and_keeps_its_extension() -> None:
    name = sanitize_filename("a" * 300 + ".txt")

    assert len(name) == 255
    assert name.endswith(".txt")


def test_a_long_name_without_an_extension_is_capped() -> None:
    assert sanitize_filename("b" * 1000) == "b" * 255
    assert len(sanitize_filename("é" * 400)) == 255


def test_a_long_extension_is_not_preserved_over_the_stem() -> None:
    name = sanitize_filename("stem." + "x" * 400)

    assert len(name) == 255


def test_capping_never_leaves_a_trailing_dot_or_space() -> None:
    name = sanitize_filename("a" * 253 + " ." + "z" * 5)

    assert len(name) <= 255
    assert name == name.strip(" .")


def test_a_reserved_name_that_gets_a_prefix_still_fits() -> None:
    name = sanitize_filename("CON" + "x" * 0 + "." + "e" * 252)

    assert len(name) <= 255
    assert name.startswith("_CON")


def test_the_result_never_contains_separators_or_control_characters() -> None:
    nasty = "a/b\\c\x00d\x1fe\x7ff\u202eg\u2066h\u200bi:j"
    cleaned = sanitize_filename(nasty)

    assert not any(ch in cleaned for ch in "/\\:\x00\x1f\x7f\u202e\u2066\u200b")


# --- Header decoding ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("report.txt", "report.txt"),
        ("caf%C3%A9.txt", "café.txt"),
        ("a%20b.txt", "a b.txt"),
        ("%E6%97%A5%E6%9C%AC%E8%AA%9E.txt", "日本語.txt"),
        ("..%2f..%2fsecret.txt", "secret.txt"),
        ("..%5c..%5csecret.txt", "secret.txt"),
        ("evil%00.txt", "evil.txt"),
        ("a%0d%0ab.txt", "ab.txt"),
        ("photo%E2%80%AEgnp.exe", "photognp.exe"),
        ("%252e%252e%252f", "%2e%2e%2f"),
    ],
)
def test_headers_are_percent_decoded_once_then_sanitised(header: str, expected: str) -> None:
    assert filename_from_header([header]) == expected


@pytest.mark.parametrize("header", ["%2e%2e%2f", "%2E%2E%2F", "..%2f", "%00", "%2f", "%20", "."])
def test_headers_that_decode_to_nothing_usable_are_rejected(header: str) -> None:
    with pytest.raises(InvalidFilename):
        filename_from_header([header])


@pytest.mark.parametrize(
    "values",
    [
        [],
        ["a.txt", "b.txt"],
        [""],
        ["%ff%fe"],
        ["%c3"],
        ["%80abc"],
        ["caf\u00e9.txt"],
        ["日本語"],
        ["a" * 1025],
    ],
)
def test_malformed_name_headers_are_rejected(values: list[str]) -> None:
    with pytest.raises(InvalidFilename):
        decode_filename_header(values)


def test_a_header_of_exactly_1024_characters_is_accepted_and_then_capped() -> None:
    assert len(decode_filename_header(["a" * 1024])) == 1024
    assert len(filename_from_header(["a" * 1024])) == 255


def test_the_error_message_never_echoes_the_name() -> None:
    with pytest.raises(InvalidFilename) as error:
        filename_from_header(["secret-name%ff"])

    assert "secret" not in str(error.value)
    assert "secret" not in repr(error.value)


# --- Content-Disposition --------------------------------------------------------------------------


def test_content_disposition_for_a_plain_name() -> None:
    assert (
        content_disposition("report.txt")
        == "attachment; filename=\"report.txt\"; filename*=UTF-8''report.txt"
    )


def test_content_disposition_carries_the_utf8_name_and_an_ascii_fallback() -> None:
    header = content_disposition("résumé 日本.pdf")

    assert header.startswith('attachment; filename="r_sum_ __.pdf"')
    assert header.endswith("filename*=UTF-8''r%C3%A9sum%C3%A9%20%E6%97%A5%E6%9C%AC.pdf")
    assert header.isascii()


@pytest.mark.parametrize(
    "hostile",
    [
        'evil"; filename="other.exe',
        "a\r\nSet-Cookie: x=1",
        "a\nX-Injected: yes",
        "back\\slash",
        "semi;colon",
        'q"uote',
        "perc%ent",
        "x\x00y",
        "tab\there",
        "' onload='alert(1)",
    ],
)
def test_content_disposition_cannot_be_broken_out_of(hostile: str) -> None:
    header = content_disposition(hostile)
    fallback = header.split('filename="', 1)[1].split('"; filename*=', 1)[0]

    assert header.isascii()
    assert "\r" not in header
    assert "\n" not in header
    assert "\x00" not in header
    assert '"' not in fallback
    assert "\\" not in fallback
    assert ";" not in fallback
    assert header.count('"') == 2
    assert header.count("; ") == 2


def test_content_disposition_of_an_empty_name_uses_a_default() -> None:
    assert content_disposition("").startswith('attachment; filename="download"')
