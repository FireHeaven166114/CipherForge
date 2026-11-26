import { describe, expect, it } from "vitest";

import {
  cleanFileName,
  FALLBACK_FILE_NAME,
  fileNameFromDisposition,
  MAX_FILE_NAME_LENGTH,
  sanitizeFileName,
} from "./disposition";

describe("fileNameFromDisposition", () => {
  it("reads the header the API sends: an ASCII fallback and the real name", () => {
    expect(fileNameFromDisposition(`attachment; filename="report.pdf"; filename*=UTF-8''report.pdf`)).toBe(
      "report.pdf",
    );
  });

  it("prefers the percent-encoded UTF-8 name (RFC 5987) over the ASCII stand-in", () => {
    const header = `attachment; filename="_ rates.txt"; filename*=UTF-8''%E2%82%AC%20rates.txt`;
    expect(fileNameFromDisposition(header)).toBe("€ rates.txt");
  });

  it("prefers it wherever it appears, and ignores a language tag", () => {
    expect(fileNameFromDisposition(`attachment; filename*=UTF-8'en'%C3%A9t%C3%A9.txt; filename="ete.txt"`)).toBe(
      "été.txt",
    );
  });

  it("reads an ISO-8859-1 extended value", () => {
    expect(fileNameFromDisposition("attachment; filename*=iso-8859-1''caf%E9.txt")).toBe("café.txt");
  });

  it("falls back to the plain name when the extended one cannot be decoded", () => {
    expect(fileNameFromDisposition(`attachment; filename="plain.txt"; filename*=UTF-8''%E2%82`)).toBe("plain.txt");
    expect(fileNameFromDisposition(`attachment; filename="plain.txt"; filename*=klingon''abc.txt`)).toBe("plain.txt");
    expect(fileNameFromDisposition(`attachment; filename="plain.txt"; filename*=garbage`)).toBe("plain.txt");
  });

  it("reads a quoted name, keeping semicolons and unescaping quotes", () => {
    expect(fileNameFromDisposition(`attachment; filename="a;b.txt"`)).toBe("a;b.txt");
    expect(fileNameFromDisposition(String.raw`attachment; filename="say \"hi\".txt"`)).toBe("say _hi_.txt");
  });

  it("reads an unquoted name and ignores the case of the parameter name", () => {
    expect(fileNameFromDisposition("attachment; filename=report.pdf")).toBe("report.pdf");
    expect(fileNameFromDisposition(`Attachment; FILENAME="Report.PDF"`)).toBe("Report.PDF");
  });

  it("calls a response with no usable name 'download'", () => {
    expect(fileNameFromDisposition(null)).toBe(FALLBACK_FILE_NAME);
    expect(fileNameFromDisposition("")).toBe(FALLBACK_FILE_NAME);
    expect(fileNameFromDisposition("attachment")).toBe(FALLBACK_FILE_NAME);
    expect(fileNameFromDisposition(`attachment; filename=""`)).toBe(FALLBACK_FILE_NAME);
    expect(fileNameFromDisposition(`attachment; filename="..."`)).toBe(FALLBACK_FILE_NAME);
  });

  it("uses the plain name when the extended one is empty after cleaning", () => {
    expect(fileNameFromDisposition(`attachment; filename="kept.txt"; filename*=UTF-8''%2F%2F`)).toBe("kept.txt");
  });

  it("cannot be steered out of the download folder", () => {
    expect(fileNameFromDisposition(String.raw`attachment; filename="..\\..\\windows\\system32\\evil.exe"`)).toBe(
      "evil.exe",
    );
    expect(fileNameFromDisposition(`attachment; filename*=UTF-8''..%2F..%2Fetc%2Fpasswd`)).toBe("passwd");
    expect(fileNameFromDisposition(`attachment; filename="/"`)).toBe(FALLBACK_FILE_NAME);
    expect(fileNameFromDisposition(`attachment; filename=".."`)).toBe(FALLBACK_FILE_NAME);
  });

  it("leaves no path separator even when a backslash is not escaped as the format asks", () => {
    const name = fileNameFromDisposition(String.raw`attachment; filename="..\..\windows\evil.exe"`);
    expect(name).not.toMatch(/[\\/]/);
    expect(name.endsWith("evil.exe")).toBe(true);
  });
});

describe("sanitizeFileName", () => {
  it("removes control characters and invisible formatting such as a right-to-left override", () => {
    expect(sanitizeFileName("a\u0000b\nc\td.txt")).toBe("abcd.txt");
    expect(sanitizeFileName("evil\u202Etxt.exe")).toBe("eviltxt.exe");
    expect(sanitizeFileName("zero\u200Bwidth.txt")).toBe("zerowidth.txt");
    expect(sanitizeFileName("line\u2028break.txt")).toBe("linebreak.txt");
  });

  it("keeps only the last path component, whichever slash is used", () => {
    expect(sanitizeFileName("a/b/c.txt")).toBe("c.txt");
    expect(sanitizeFileName(String.raw`C:\Users\me\c.txt`)).toBe("c.txt");
    expect(sanitizeFileName("folder/")).toBe("folder");
  });

  it("replaces characters Windows refuses", () => {
    expect(sanitizeFileName(`a<b>c:d"e|f?g*h.txt`)).toBe("a_b_c_d_e_f_g_h.txt");
  });

  it("trims leading and trailing dots and spaces", () => {
    expect(sanitizeFileName("  ..hidden.txt. . ")).toBe("hidden.txt");
  });

  it("does not let a name be a Windows device", () => {
    expect(sanitizeFileName("CON")).toBe("_CON");
    expect(sanitizeFileName("nul.txt")).toBe("_nul.txt");
    expect(sanitizeFileName("com1.log")).toBe("_com1.log");
    expect(sanitizeFileName("LPT9")).toBe("_LPT9");
    expect(sanitizeFileName("console.txt")).toBe("console.txt");
    expect(sanitizeFileName("com10.txt")).toBe("com10.txt");
  });

  it("replaces a surrogate half that has no partner, and keeps a real pair", () => {
    expect(sanitizeFileName("a\uD800b.txt")).toBe("a_b.txt");
    expect(sanitizeFileName("a\uDC00b.txt")).toBe("a_b.txt");
    expect(sanitizeFileName("smile \u{1F600}.txt")).toBe("smile \u{1F600}.txt");
  });

  it("limits the length but keeps a short extension", () => {
    const long = sanitizeFileName(`${"a".repeat(400)}.pdf`);
    expect(Array.from(long)).toHaveLength(MAX_FILE_NAME_LENGTH);
    expect(long.endsWith(".pdf")).toBe(true);

    const noExtension = sanitizeFileName("b".repeat(400));
    expect(Array.from(noExtension)).toHaveLength(MAX_FILE_NAME_LENGTH);

    const emoji = sanitizeFileName("\u{1F600}".repeat(300));
    expect(Array.from(emoji)).toHaveLength(MAX_FILE_NAME_LENGTH);
  });

  it("truncates a long extension as part of the name instead of keeping it", () => {
    const name = sanitizeFileName(`a.${"x".repeat(300)}`);
    expect(Array.from(name)).toHaveLength(MAX_FILE_NAME_LENGTH);
    expect(name.startsWith("a.xxx")).toBe(true);
  });

  it("falls back to 'download' when nothing is left", () => {
    for (const name of ["", " ", ".", "..", "...", "/", "\\", "\u0000", "\u202E", " . "]) {
      expect(sanitizeFileName(name)).toBe(FALLBACK_FILE_NAME);
    }
  });

  it("gives the same answer when applied twice", () => {
    for (const name of ["CON.txt", "..\\..\\x.exe", "a<b>.txt", `${"é".repeat(300)}.tar.gz`, "  .x. ", "plain.pdf"]) {
      const once = sanitizeFileName(name);
      expect(sanitizeFileName(once)).toBe(once);
    }
  });
});

describe("cleanFileName", () => {
  it("returns null, not the fallback, so a caller can try another candidate", () => {
    expect(cleanFileName("..")).toBeNull();
    expect(cleanFileName("report.pdf")).toBe("report.pdf");
  });
});
