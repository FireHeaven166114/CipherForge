import { afterEach, describe, expect, it, vi } from "vitest";

import { hangingFetch, jsonResponse, stubFetch } from "../test/http";
import {
  ApiError,
  downloadFile,
  request,
  requestNoContent,
  setTokenProvider,
  toApiError,
  uploadFile,
} from "./apiClient";

afterEach(() => {
  setTokenProvider(null);
});

async function failureOf(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  throw new Error("expected the request to fail");
}

describe("request", () => {
  it("returns parsed JSON using safe request defaults", async () => {
    const fetchMock = stubFetch(() => jsonResponse({ hello: "world" }));

    await expect(request<{ hello: string }>("/api/v1/thing")).resolves.toEqual({ hello: "world" });

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/thing",
      expect.objectContaining({
        method: "GET",
        cache: "no-store",
        credentials: "same-origin",
        headers: { Accept: "application/json" },
      }),
    );
  });

  it("sends JSON bodies with a content type", async () => {
    const fetchMock = stubFetch(() => jsonResponse({ ok: true }));

    await request("/api/v1/thing", { method: "POST", body: { indicator: "1.1.1.1" } });

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/thing",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ indicator: "1.1.1.1" }),
        headers: { Accept: "application/json", "Content-Type": "application/json" },
      }),
    );
  });

  it("attaches a bearer token only while a provider is registered", async () => {
    const fetchMock = stubFetch(() => jsonResponse({}));

    setTokenProvider(() => "token-123");
    await request("/api/v1/thing");
    setTokenProvider(null);
    await request("/api/v1/thing");

    const [withToken, withoutToken] = fetchMock.mock.calls;
    expect(withToken?.[1]?.headers).toMatchObject({ Authorization: "Bearer token-123" });
    expect(withoutToken?.[1]?.headers).not.toHaveProperty("Authorization");
  });

  it("maps the error envelope to an ApiError and never surfaces other body content", async () => {
    stubFetch(() =>
      jsonResponse(
        {
          error: { code: "forbidden", message: "Insufficient role.", correlation_id: "corr-1234" },
          internal: "stack trace and secrets",
        },
        { status: 403 },
      ),
    );

    const error = await failureOf(request("/api/v1/thing"));

    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({
      status: 403,
      code: "forbidden",
      message: "Insufficient role.",
      correlationId: "corr-1234",
    });
    expect((error as ApiError).message).not.toContain("secrets");
  });

  it("falls back to a generic message for non-JSON error bodies", async () => {
    stubFetch(
      () =>
        new Response("<html>upstream internal-host-7 exploded</html>", {
          status: 502,
          headers: { "X-Correlation-ID": "header-corr-1" },
        }),
    );

    const error = await failureOf(request("/api/v1/thing"));

    expect(error).toMatchObject({
      status: 502,
      code: "http_error",
      message: "The API responded with HTTP 502.",
      correlationId: "header-corr-1",
    });
    expect((error as ApiError).message).not.toContain("internal-host-7");
  });

  it("reads how long to wait from Retry-After and ignores values it cannot trust", async () => {
    const limited = (retryAfter?: string) =>
      jsonResponse(
        { error: { code: "rate_limited", message: "Too many investigations." } },
        { status: 429, headers: retryAfter ? { "Retry-After": retryAfter } : {} },
      );

    stubFetch(() => limited("17"));
    await expect(failureOf(request("/api/v1/thing"))).resolves.toMatchObject({
      status: 429,
      code: "rate_limited",
      retryAfterSeconds: 17,
    });

    stubFetch(() => limited("9999999"));
    await expect(failureOf(request("/api/v1/thing"))).resolves.toMatchObject({
      retryAfterSeconds: 3600,
    });

    for (const value of [undefined, "soon", "-5", "1.5", "Wed, 21 Oct 2026 07:28:00 GMT"]) {
      stubFetch(() => limited(value));
      await expect(failureOf(request("/api/v1/thing"))).resolves.toMatchObject({
        retryAfterSeconds: undefined,
      });
    }
  });

  it("treats listed non-2xx statuses as results", async () => {
    stubFetch(() => jsonResponse({ status: "not_ready" }, { status: 503 }));

    await expect(request("/ready", { acceptStatuses: [503] })).resolves.toEqual({
      status: "not_ready",
    });
    await expect(failureOf(request("/ready"))).resolves.toMatchObject({ status: 503 });
  });

  it("rejects a body that fails the guard", async () => {
    stubFetch(() => jsonResponse({ unexpected: true }));
    const isThing = (value: unknown): value is { name: string } =>
      typeof value === "object" && value !== null && "name" in value;

    const error = await failureOf(request("/api/v1/thing", { guard: isThing }));

    expect(error).toMatchObject({ code: "invalid_response" });
  });

  it("reports an unreadable success body as invalid_response", async () => {
    stubFetch(() => new Response("<html>login page</html>", { status: 200 }));

    await expect(failureOf(request("/api/v1/thing"))).resolves.toMatchObject({
      code: "invalid_response",
    });
  });

  it("reports connection failures as network_error", async () => {
    stubFetch(() => Promise.reject(new TypeError("Failed to fetch")));

    await expect(failureOf(request("/api/v1/thing"))).resolves.toMatchObject({
      status: 0,
      code: "network_error",
      message: "Could not reach the CipherForge API.",
    });
  });

  it("times out slow requests", async () => {
    stubFetch(hangingFetch());

    await expect(failureOf(request("/api/v1/thing", { timeoutMs: 20 }))).resolves.toMatchObject({
      code: "timeout",
    });
  });

  it("rethrows the abort untouched when the caller cancels", async () => {
    stubFetch(hangingFetch());
    const controller = new AbortController();

    const pending = failureOf(request("/api/v1/thing", { signal: controller.signal }));
    controller.abort();

    const error = await pending;
    expect(error).not.toBeInstanceOf(ApiError);
    expect(controller.signal.aborted).toBe(true);
  });
});

describe("toApiError", () => {
  it("keeps an ApiError and wraps anything else without leaking its message", () => {
    const original = new ApiError({ message: "Nope.", status: 403, code: "forbidden" });
    expect(toApiError(original)).toBe(original);

    const wrapped = toApiError(new TypeError("secret internal detail"));
    expect(wrapped).toBeInstanceOf(ApiError);
    expect(wrapped).toMatchObject({ status: 0, code: "unexpected_error" });
    expect(wrapped.message).not.toContain("secret");
  });
});

describe("authenticated: false", () => {
  it("never attaches the bearer token, even when a provider is registered", async () => {
    const fetchMock = stubFetch(() => jsonResponse({ ok: true }));
    const provider = vi.fn(() => "token-123");
    setTokenProvider(provider);

    await request("/api/v1/shares/abc", { authenticated: false });
    await downloadFile("/api/v1/shares/abc/download", { method: "POST", authenticated: false }).catch(
      () => undefined,
    );

    for (const call of fetchMock.mock.calls) {
      expect(call[1]?.headers).not.toHaveProperty("Authorization");
    }
    expect(provider).not.toHaveBeenCalled();
  });
});

describe("requestNoContent", () => {
  it("resolves on 204 and sends a DELETE by default", async () => {
    const fetchMock = stubFetch(() => new Response(null, { status: 204 }));

    await expect(requestNoContent("/api/v1/files/abc")).resolves.toBeUndefined();

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/files/abc",
      expect.objectContaining({ method: "DELETE", cache: "no-store" }),
    );
  });

  it("attaches the bearer token and maps an error envelope", async () => {
    const fetchMock = stubFetch(() =>
      jsonResponse(
        { error: { code: "session_running", message: "Stop it first.", correlation_id: "c-1" } },
        { status: 409 },
      ),
    );
    setTokenProvider(() => "token-9");

    const error = await failureOf(requestNoContent("/api/v1/network/sessions/abc"));

    expect(error).toMatchObject({ status: 409, code: "session_running", correlationId: "c-1" });
    expect(fetchMock.mock.calls[0]?.[1]?.headers).toMatchObject({ Authorization: "Bearer token-9" });
  });

  it("falls back to a generic error for a non-JSON failure", async () => {
    stubFetch(() => new Response("<html>bad gateway</html>", { status: 502 }));

    await expect(failureOf(requestNoContent("/api/v1/files/abc"))).resolves.toMatchObject({
      status: 502,
      code: "http_error",
    });
  });
});

describe("uploadFile", () => {
  const isFile = (value: unknown): value is { id: string } =>
    typeof value === "object" && value !== null && "id" in value;

  it("sends the raw bytes as octet-stream with the name percent-encoded", async () => {
    const fetchMock = stubFetch(() => jsonResponse({ id: "f1" }, { status: 201 }));
    const file = new Blob(["hello"], { type: "text/plain" });

    await expect(
      uploadFile("/api/v1/files", file, { fileName: "résumé #1/ü.txt", guard: isFile }),
    ).resolves.toEqual({ id: "f1" });

    const init = fetchMock.mock.calls[0]?.[1];
    expect(init?.method).toBe("POST");
    expect(init?.body).toBe(file);
    expect(init?.headers).toMatchObject({
      "Content-Type": "application/octet-stream",
      "X-File-Name": encodeURIComponent("résumé #1/ü.txt"),
    });
    expect((init?.headers as Record<string, string>)["X-File-Name"]).not.toMatch(/[^\x21-\x7e]/);
  });

  it("maps the error envelope, including Retry-After", async () => {
    stubFetch(() =>
      jsonResponse(
        { error: { code: "rate_limited", message: "Slow down." } },
        { status: 429, headers: { "Retry-After": "12" } },
      ),
    );

    await expect(
      failureOf(uploadFile("/api/v1/files", new Blob(["x"]), { fileName: "a.txt" })),
    ).resolves.toMatchObject({ status: 429, code: "rate_limited", retryAfterSeconds: 12 });
  });

  it("rejects an answer that fails the guard or is not JSON", async () => {
    stubFetch(() => jsonResponse({ nope: true }, { status: 201 }));
    await expect(
      failureOf(uploadFile("/api/v1/files", new Blob(["x"]), { fileName: "a", guard: isFile })),
    ).resolves.toMatchObject({ code: "invalid_response" });

    stubFetch(() => new Response("<html></html>", { status: 201 }));
    await expect(
      failureOf(uploadFile("/api/v1/files", new Blob(["x"]), { fileName: "a" })),
    ).resolves.toMatchObject({ code: "invalid_response" });
  });

  it("times out and can be cancelled", async () => {
    stubFetch(hangingFetch());
    await expect(
      failureOf(uploadFile("/api/v1/files", new Blob(["x"]), { fileName: "a", timeoutMs: 20 })),
    ).resolves.toMatchObject({ code: "timeout" });

    const controller = new AbortController();
    const pending = failureOf(
      uploadFile("/api/v1/files", new Blob(["x"]), { fileName: "a", signal: controller.signal }),
    );
    controller.abort();
    expect(await pending).not.toBeInstanceOf(ApiError);
  });
});

describe("downloadFile", () => {
  it("returns the bytes and the Content-Disposition header", async () => {
    const fetchMock = stubFetch(
      () =>
        new Response(new Uint8Array([1, 2, 3]), {
          status: 200,
          headers: {
            "Content-Type": "application/octet-stream",
            "Content-Disposition": "attachment; filename=\"report.pdf\"",
          },
        }),
    );

    const result = await downloadFile("/api/v1/shares/abc/download", {
      method: "POST",
      body: { password: "correct horse" },
      authenticated: false,
    });

    expect(result.contentDisposition).toBe("attachment; filename=\"report.pdf\"");
    expect(new Uint8Array(await result.data.arrayBuffer())).toEqual(new Uint8Array([1, 2, 3]));
    const init = fetchMock.mock.calls[0]?.[1];
    expect(init?.method).toBe("POST");
    expect(init?.body).toBe(JSON.stringify({ password: "correct horse" }));
    expect(init?.headers).toMatchObject({ "Content-Type": "application/json" });
  });

  it("sends no body or content type for a plain GET and reports a missing disposition as null", async () => {
    const fetchMock = stubFetch(() => new Response(new Uint8Array([9]), { status: 200 }));

    const result = await downloadFile("/api/v1/shares/abc/download");

    expect(result.contentDisposition).toBeNull();
    expect(fetchMock.mock.calls[0]?.[1]?.body).toBeUndefined();
    expect(fetchMock.mock.calls[0]?.[1]?.headers).not.toHaveProperty("Content-Type");
  });

  it("surfaces the JSON error envelope of a refused download", async () => {
    stubFetch(() =>
      jsonResponse(
        { error: { code: "invalid_password", message: "The password is not correct." } },
        { status: 403, headers: { "X-Correlation-ID": "c-77" } },
      ),
    );

    await expect(
      failureOf(downloadFile("/api/v1/shares/abc/download", { method: "POST", body: {} })),
    ).resolves.toMatchObject({ status: 403, code: "invalid_password", message: "The password is not correct." });
  });

  it("reports a body that cannot be read as invalid_response", async () => {
    const broken = new Response(null, { status: 200 });
    vi.spyOn(broken, "blob").mockRejectedValue(new TypeError("stream failed"));
    stubFetch(() => broken);

    await expect(failureOf(downloadFile("/api/v1/shares/abc/download"))).resolves.toMatchObject({
      code: "invalid_response",
    });
  });
});
