import { describe, expect, it } from "vitest";

import { ApiError } from "../../services/apiClient";
import {
  describeErrorCode,
  describeNetworkError,
  NETWORK_GUIDE,
  networkErrorMessage,
} from "./messages";

function failure(status: number, code: string, extra: { retryAfterSeconds?: number } = {}): ApiError {
  return new ApiError({ message: `API says ${code}`, status, code, ...extra });
}

const CODES: readonly [string, number][] = [
  ["capture_permission_denied", 503],
  ["capture_backend_missing", 503],
  ["interface_unavailable", 503],
  ["capture_failed", 503],
  ["interrupted", 503],
  ["invalid_capture_file", 422],
  ["capture_truncated", 422],
  ["analysis_timeout", 503],
  ["analysis_failed", 503],
  ["results_incomplete", 503],
  ["interface_not_found", 404],
  ["capture_already_running", 409],
  ["capture_not_running", 409],
  ["analysis_already_running", 409],
  ["session_not_found", 404],
  ["session_running", 409],
  ["alert_not_found", 404],
  ["enrichment_disabled", 409],
  ["address_not_public", 422],
  ["invalid_filename", 422],
  ["file_too_large", 413],
  ["invalid_content_length", 400],
  ["upload_interrupted", 400],
];

describe("describeNetworkError", () => {
  it.each(CODES)("has a calm message of its own for %s", (code, status) => {
    const mapped = describeNetworkError(failure(status, code));
    expect(mapped).not.toBeNull();
    expect(mapped?.title).not.toBe("");
    expect(mapped?.message).not.toBe(`API says ${code}`);
    expect(mapped?.message.endsWith(".")).toBe(true);
  });

  it("explains a permission refusal without a link and points at the guide as text", () => {
    const mapped = describeNetworkError(failure(503, "capture_permission_denied"));
    expect(mapped?.message).toContain("operating system refused packet capture");
    expect(mapped?.message).toContain("differ by platform");
    expect(mapped?.message).toContain(NETWORK_GUIDE);
  });

  it("names the packet-capture libraries when none is installed", () => {
    const mapped = describeNetworkError(failure(503, "capture_backend_missing"));
    expect(mapped?.message).toContain("Npcap");
    expect(mapped?.message).toContain("libpcap");
  });

  it("names the upload limit when it is known", () => {
    expect(describeNetworkError(failure(413, "file_too_large"), { maxUploadMb: 50 })?.message).toContain(
      "50 MB",
    );
    expect(describeNetworkError(failure(413, "file_too_large"))?.message).toContain("the upload limit");
    expect(describeNetworkError(failure(413, "payload_too_large"), { maxUploadMb: 8 })?.message).toContain(
      "8 MB",
    );
  });

  it("maps statuses that carry no code of their own", () => {
    expect(describeNetworkError(failure(401, "unauthorized"))?.message).toContain("security analyst role");
    expect(describeNetworkError(failure(403, "forbidden"))?.title).toBe("Security analyst role needed");
    expect(describeNetworkError(failure(415, "bad_type"))?.title).toBe("Upload type not accepted");
  });

  it("tells a rate-limited caller how long to wait", () => {
    expect(
      describeNetworkError(failure(429, "rate_limited", { retryAfterSeconds: 30 }))?.message,
    ).toContain("30 seconds");
    expect(
      describeNetworkError(failure(429, "rate_limited", { retryAfterSeconds: 120 }))?.message,
    ).toContain("2 minutes");
    expect(describeNetworkError(failure(429, "rate_limited"))?.message).toContain("a moment");
  });

  it("prefers the code over the status", () => {
    expect(describeNetworkError(failure(403, "session_not_found"))?.title).toBe("Session not found");
  });

  it("leaves outages, timeouts and unknown codes to the API's own message", () => {
    expect(describeNetworkError(failure(0, "timeout"))).toBeNull();
    expect(describeNetworkError(failure(0, "network_error"))).toBeNull();
    expect(describeNetworkError(failure(500, "internal_error"))).toBeNull();
    expect(describeNetworkError(failure(422, "something_new"))).toBeNull();
    expect(describeNetworkError(failure(400, "constructor"))).toBeNull();
  });
});

describe("networkErrorMessage", () => {
  it("uses the calm wording when there is some, else the API's message", () => {
    expect(networkErrorMessage(failure(409, "session_running"))).toContain("still running");
    expect(networkErrorMessage(failure(500, "internal_error"))).toBe("API says internal_error");
  });
});

describe("describeErrorCode", () => {
  it("words the reason a session or capture ended, the same way as the errors", () => {
    expect(describeErrorCode("capture_truncated")?.message).toContain("Everything before that point was analysed");
    expect(describeErrorCode("interrupted")?.message).toContain("ended early");
    expect(describeErrorCode("results_incomplete")?.message).toContain("totals may be incomplete");
  });

  it("knows nothing about a missing or unknown code", () => {
    expect(describeErrorCode(null)).toBeNull();
    expect(describeErrorCode(undefined)).toBeNull();
    expect(describeErrorCode("brand_new_code")).toBeNull();
    expect(describeErrorCode("__proto__")).toBeNull();
  });
});
