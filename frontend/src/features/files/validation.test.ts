import { describe, expect, it } from "vitest";

import { makeFileStatus } from "../../test/filesFixtures";
import { formatBytes } from "../units";
import {
  defaultShareValues,
  MAX_NAME_HEADER_LENGTH,
  passwordLength,
  validatePassword,
  validateShareForm,
  validateUpload,
} from "./validation";

const STATUS = makeFileStatus();

function values(overrides: Partial<ReturnType<typeof defaultShareValues>> = {}) {
  return { ...defaultShareValues(STATUS), ...overrides };
}

describe("defaultShareValues", () => {
  it("starts from the server's default expiry and a single download, with no password", () => {
    expect(defaultShareValues(STATUS)).toEqual({ expiresInHours: "24", maxDownloads: "1", password: "" });
    expect(defaultShareValues(makeFileStatus({ default_share_expiry_hours: 72 })).expiresInHours).toBe("72");
  });

  it("never starts above the longest expiry the server allows", () => {
    const status = makeFileStatus({ default_share_expiry_hours: 48, max_share_expiry_hours: 12 });
    expect(defaultShareValues(status).expiresInHours).toBe("12");
  });
});

describe("validateShareForm", () => {
  it("accepts the defaults and sends numbers, with no password key at all", () => {
    const { errors, request } = validateShareForm(values(), STATUS);

    expect(errors).toEqual({});
    expect(request).toEqual({ expires_in_hours: 24, max_downloads: 1 });
    expect(request).not.toHaveProperty("password");
    expect(typeof request?.expires_in_hours).toBe("number");
    expect(typeof request?.max_downloads).toBe("number");
  });

  it("sends the password exactly as typed, spaces included, only when one was typed", () => {
    const { request } = validateShareForm(values({ password: "  correct horse  " }), STATUS);
    expect(request?.password).toBe("  correct horse  ");
  });

  it("trims the numbers but not the password", () => {
    const { request } = validateShareForm(values({ expiresInHours: " 12 ", maxDownloads: "\t5\n" }), STATUS);
    expect(request).toMatchObject({ expires_in_hours: 12, max_downloads: 5 });
  });

  it("accepts the limits themselves", () => {
    expect(validateShareForm(values({ expiresInHours: "1", maxDownloads: "1" }), STATUS).request).not.toBeNull();
    expect(validateShareForm(values({ expiresInHours: "720", maxDownloads: "100" }), STATUS).request).not.toBeNull();
  });

  it.each(["", " ", "0", "721", "-1", "1.5", "1e2", "abc", "12h", "+5", "99999999999", "\u0663"])(
    "rejects %j hours, naming the range",
    (hours) => {
      const { errors, request } = validateShareForm(values({ expiresInHours: hours }), STATUS);
      expect(errors.expiresInHours).toBe("Enter a whole number of hours from 1 to 720.");
      expect(request).toBeNull();
    },
  );

  it.each(["", "0", "101", "-3", "2.5", "many"])("rejects %j downloads, naming the range", (downloads) => {
    const { errors, request } = validateShareForm(values({ maxDownloads: downloads }), STATUS);
    expect(errors.maxDownloads).toBe("Enter a whole number of downloads from 1 to 100.");
    expect(request).toBeNull();
  });

  it("reports every wrong field at once", () => {
    const { errors, request } = validateShareForm(
      { expiresInHours: "0", maxDownloads: "0", password: "short" },
      STATUS,
    );
    expect(Object.keys(errors).sort()).toEqual(["expiresInHours", "maxDownloads", "password"]);
    expect(request).toBeNull();
  });

  it("uses the limits of the status it is given", () => {
    const status = makeFileStatus({ max_share_expiry_hours: 6, max_share_downloads: 2, min_password_length: 12 });
    const { errors } = validateShareForm({ expiresInHours: "7", maxDownloads: "3", password: "elevenchars" }, status);
    expect(errors.expiresInHours).toContain("1 to 6");
    expect(errors.maxDownloads).toContain("1 to 2");
    expect(errors.password).toContain("12");
  });
});

describe("validatePassword", () => {
  it("allows no password at all, but not one that is too short or too long", () => {
    expect(validatePassword("", STATUS)).toBeNull();
    expect(validatePassword("1234567", STATUS)).toBe(
      "Use at least 8 characters, or leave the password empty for no password.",
    );
    expect(validatePassword("12345678", STATUS)).toBeNull();
    expect(validatePassword("x".repeat(128), STATUS)).toBeNull();
    expect(validatePassword("x".repeat(129), STATUS)).toBe("Use at most 128 characters.");
  });

  it("counts characters the way a person does, not UTF-16 units", () => {
    expect(passwordLength("\u{1F600}".repeat(8))).toBe(8);
    expect(validatePassword("\u{1F600}".repeat(8), STATUS)).toBeNull();
    expect(validatePassword("\u{1F600}".repeat(7), STATUS)).not.toBeNull();
    expect(validatePassword("\u{1F600}".repeat(129), STATUS)).not.toBeNull();
  });

  it("refuses text the server would reject, such as half of a surrogate pair", () => {
    expect(validatePassword(`password\uD800`, STATUS)).toBe(
      "The password contains a character that cannot be sent. Remove it and try again.",
    );
  });
});

describe("validateUpload", () => {
  const MAX = 25 * 1024 * 1024;

  function file(name: string, size: number) {
    return { name, size };
  }

  it("accepts a file the server will take, up to the limit itself", () => {
    expect(validateUpload(file("report.pdf", 2048), MAX)).toBeNull();
    expect(validateUpload(file("report.pdf", MAX), MAX)).toBeNull();
  });

  it("refuses an empty file", () => {
    expect(validateUpload(file("empty.txt", 0), MAX)).toBe("That file is empty, so there is nothing to encrypt.");
  });

  it("refuses a file over the limit, with both sizes", () => {
    const message = validateUpload(file("big.bin", MAX + 1), MAX);
    expect(message).toContain(formatBytes(MAX + 1));
    expect(message).toContain(formatBytes(MAX));
  });

  it("does not check the size when the limit is not known yet", () => {
    expect(validateUpload(file("big.bin", MAX * 10), undefined)).toBeNull();
  });

  it("refuses a name that is empty or whose encoded form is too long for the header", () => {
    expect(validateUpload(file("   ", 10), MAX)).toMatch(/no name/);

    const fits = "\u00E9".repeat(Math.floor(MAX_NAME_HEADER_LENGTH / 6));
    expect(encodeURIComponent(fits).length).toBeLessThanOrEqual(MAX_NAME_HEADER_LENGTH);
    expect(validateUpload(file(fits, 10), MAX)).toBeNull();

    const tooLong = `${fits}\u00E9\u00E9`;
    expect(validateUpload(file(tooLong, 10), MAX)).toMatch(/too long/);
  });

  it("refuses a name that cannot be encoded for the header", () => {
    expect(validateUpload(file("bad\uD800name.txt", 10), MAX)).toMatch(/cannot be sent/);
  });
});
