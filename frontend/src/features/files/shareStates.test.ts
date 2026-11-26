import { describe, expect, it } from "vitest";

import { ApiError } from "../../services/apiClient";
import { classifyShareError, SHARE_STATE_TEXT, type ShareFailureKind } from "./shareStates";

function failure(code: string, status: number, extra: { retryAfterSeconds?: number; correlationId?: string } = {}) {
  return new ApiError({ message: "raw", status, code, ...extra });
}

describe("classifyShareError", () => {
  it.each<[string, number, ShareFailureKind]>([
    ["share_not_found", 404, "not_found"],
    ["share_revoked", 410, "revoked"],
    ["share_expired", 410, "expired"],
    ["share_limit_reached", 410, "limit_reached"],
    ["file_unavailable", 409, "integrity"],
    ["password_required", 403, "password_required"],
    ["invalid_password", 403, "wrong_password"],
    ["rate_limited", 429, "rate_limited"],
    ["too_many_attempts", 429, "rate_limited"],
    ["feature_not_configured", 503, "unavailable"],
    ["encryption_key_mismatch", 503, "unavailable"],
    ["storage_unavailable", 503, "unavailable"],
    ["service_busy", 503, "busy"],
    ["network_error", 0, "network"],
    ["timeout", 0, "network"],
  ])("sorts %s (%i) as %s", (code, status, kind) => {
    expect(classifyShareError(failure(code, status)).kind).toBe(kind);
  });

  it("falls back on the status when the code is not one the API sends", () => {
    expect(classifyShareError(failure("http_error", 404)).kind).toBe("not_found");
    expect(classifyShareError(failure("http_error", 410)).kind).toBe("not_found");
    expect(classifyShareError(failure("http_error", 429)).kind).toBe("rate_limited");
    expect(classifyShareError(failure("http_error", 502)).kind).toBe("unavailable");
    expect(classifyShareError(failure("http_error", 504)).kind).toBe("unavailable");
    expect(classifyShareError(failure("http_error", 500)).kind).toBe("unknown");
    expect(classifyShareError(failure("invalid_response", 200)).kind).toBe("unknown");
  });

  it("passes on the wait only when the recipient is being told to wait", () => {
    expect(classifyShareError(failure("too_many_attempts", 429, { retryAfterSeconds: 42 })).waitSeconds).toBe(42);
    expect(classifyShareError(failure("service_busy", 503, { retryAfterSeconds: 2 })).waitSeconds).toBe(2);
    expect(classifyShareError(failure("share_expired", 410, { retryAfterSeconds: 42 })).waitSeconds).toBeUndefined();
    expect(classifyShareError(failure("rate_limited", 429)).waitSeconds).toBeUndefined();
  });

  it("keeps the correlation id as the reference", () => {
    expect(classifyShareError(failure("share_not_found", 404, { correlationId: "req-123" })).reference).toBe("req-123");
    expect(classifyShareError(failure("share_not_found", 404)).reference).toBeUndefined();
  });
});

describe("SHARE_STATE_TEXT", () => {
  const kinds = Object.keys(SHARE_STATE_TEXT) as ShareFailureKind[];

  it("words every state, each with its own title", () => {
    expect(new Set(kinds.map((kind) => SHARE_STATE_TEXT[kind].title)).size).toBe(kinds.length);
    for (const kind of kinds) {
      expect(SHARE_STATE_TEXT[kind].message.length).toBeGreaterThan(20);
    }
  });

  it("ends the visit only where nothing the recipient does could change the answer", () => {
    const terminal = kinds.filter((kind) => SHARE_STATE_TEXT[kind].terminal).sort();
    expect(terminal).toEqual(["expired", "integrity", "limit_reached", "not_found", "revoked"]);
    for (const kind of terminal) expect(SHARE_STATE_TEXT[kind].retry).toBe(false);
  });

  it("says that an unverifiable file was not released", () => {
    expect(SHARE_STATE_TEXT.integrity.title).toBe("This file could not be verified and was not released");
  });

  it("reveals no more about a wrong password than that it is wrong", () => {
    expect(SHARE_STATE_TEXT.wrong_password.title).toBe("That password is not correct");
    expect(SHARE_STATE_TEXT.wrong_password.message).toBe("Check the password you were given and try again.");
  });

  it("keeps server settings and internals away from a stranger", () => {
    for (const kind of kinds) {
      const { title, message } = SHARE_STATE_TEXT[kind];
      expect(`${title} ${message}`).not.toMatch(/CIPHERFORGE_|master key|\.env|docs\/|administrator/i);
    }
  });
});
