import { describe, expect, it } from "vitest";

import { ApiError } from "../../services/apiClient";
import { formatBytes } from "../units";
import { describeFileError, MASTER_KEY_SETTING } from "./messages";

function failure(code: string, status: number, extra: { retryAfterSeconds?: number; message?: string } = {}) {
  return new ApiError({ message: extra.message ?? `raw ${code}`, status, code, ...extra });
}

const LIMIT = 25 * 1024 * 1024;

describe("describeFileError", () => {
  it("states the size limit when a file is too large", () => {
    for (const code of ["file_too_large", "request_too_large"]) {
      const message = describeFileError(failure(code, 413), { maxFileSizeBytes: LIMIT });
      expect(message).toContain(formatBytes(LIMIT));
    }
    expect(describeFileError(failure("file_too_large", 413))).toMatch(/larger than this server accepts/);
  });

  it("recognises a proxy's own 413, which has no API error code", () => {
    const message = describeFileError(failure("http_error", 413), { maxFileSizeBytes: LIMIT });
    expect(message).toContain(formatBytes(LIMIT));
  });

  it("names the master key setting when files are not configured, and only then", () => {
    expect(describeFileError(failure("feature_not_configured", 503))).toContain(MASTER_KEY_SETTING);
    expect(describeFileError(failure("encryption_key_mismatch", 503))).toContain(MASTER_KEY_SETTING);
    expect(describeFileError(failure("empty_file", 422))).not.toContain(MASTER_KEY_SETTING);
  });

  it("gives the wait the server asked for when it is rate limiting", () => {
    expect(describeFileError(failure("rate_limited", 429, { retryAfterSeconds: 30 }))).toBe(
      "Too many requests. Try again in 30 seconds.",
    );
    expect(describeFileError(failure("rate_limited", 429))).toBe("Too many requests. Try again shortly.");
    expect(describeFileError(failure("http_error", 429, { retryAfterSeconds: 120 }))).toBe(
      "Too many requests. Try again in 2 minutes.",
    );
  });

  it("explains the other upload and share failures in words of its own", () => {
    const codes: [string, number][] = [
      ["empty_file", 422],
      ["invalid_filename", 422],
      ["unsupported_media_type", 415],
      ["invalid_content_length", 400],
      ["upload_interrupted", 400],
      ["file_not_found", 404],
      ["share_not_found", 404],
      ["file_unavailable", 409],
      ["service_busy", 503],
      ["storage_unavailable", 503],
      ["validation_error", 422],
      ["network_error", 0],
      ["timeout", 0],
    ];
    const messages = codes.map(([code, status]) => describeFileError(failure(code, status)));
    for (const message of messages) {
      expect(message).not.toMatch(/^raw /);
      expect(message.length).toBeGreaterThan(20);
    }
    expect(new Set(messages).size).toBe(codes.length - 1);
  });

  it("falls back on the status, then on the API's own message", () => {
    expect(describeFileError(failure("unauthenticated", 401))).toMatch(/not signed in/);
    expect(describeFileError(failure("forbidden", 403))).toMatch(/not allowed/);
    expect(describeFileError(failure("anything", 422))).toMatch(/did not accept/);
    expect(describeFileError(failure("anything", 500))).toMatch(/reported an error/);
    expect(describeFileError(failure("anything", 400, { message: "Custom words." }))).toBe("Custom words.");
    expect(describeFileError(failure("anything", 400, { message: "" }))).toBe("The request failed. Try again.");
  });
});
