import { afterEach, describe, expect, it, vi } from "vitest";

import { jsonResponse, stubFetch } from "../test/http";
import { SHARE_TOKEN, makePublicShareInfo } from "../test/filesFixtures";
import { setTokenProvider } from "./apiClient";
import { downloadShare, getShareInfo } from "./shareService";

afterEach(() => {
  setTokenProvider(null);
});

describe("getShareInfo", () => {
  it("reads what the link offers without ever sending the signed-in token", async () => {
    const info = makePublicShareInfo();
    const fetchMock = stubFetch(() => jsonResponse(info));
    const provider = vi.fn(() => "analyst-token");
    setTokenProvider(provider);

    await expect(getShareInfo(SHARE_TOKEN)).resolves.toEqual(info);

    expect(String(fetchMock.mock.calls[0]?.[0])).toBe(`/api/v1/shares/${SHARE_TOKEN}`);
    expect(fetchMock.mock.calls[0]?.[1]?.headers).not.toHaveProperty("Authorization");
    expect(provider).not.toHaveBeenCalled();
  });

  it("encodes the token so it can never change the path", async () => {
    const fetchMock = stubFetch(() => jsonResponse(makePublicShareInfo()));

    await getShareInfo("a/../b?c=1");

    expect(String(fetchMock.mock.calls[0]?.[0])).toBe("/api/v1/shares/a%2F..%2Fb%3Fc%3D1");
  });

  it("reports an answer of the wrong shape as invalid", async () => {
    stubFetch(() => jsonResponse({ state: "available" }));

    await expect(getShareInfo(SHARE_TOKEN)).rejects.toMatchObject({ code: "invalid_response" });
  });

  it("surfaces a link that is no longer valid", async () => {
    stubFetch(() =>
      jsonResponse({ error: { code: "share_expired", message: "This link has expired." } }, { status: 410 }),
    );

    await expect(getShareInfo(SHARE_TOKEN)).rejects.toMatchObject({
      status: 410,
      code: "share_expired",
    });
  });
});

describe("downloadShare", () => {
  it("posts the password in the body, never in the address, and sends no token", async () => {
    const fetchMock = stubFetch(
      () =>
        new Response(new Uint8Array([1, 2, 3]), {
          headers: { "Content-Disposition": "attachment; filename=\"report.pdf\"" },
        }),
    );
    const provider = vi.fn(() => "analyst-token");
    setTokenProvider(provider);

    const result = await downloadShare(SHARE_TOKEN, "correct horse");

    const [url, init] = fetchMock.mock.calls[0] ?? [];
    expect(String(url)).toBe(`/api/v1/shares/${SHARE_TOKEN}/download`);
    expect(String(url)).not.toContain("correct");
    expect(init?.method).toBe("POST");
    expect(init?.body).toBe(JSON.stringify({ password: "correct horse" }));
    expect(init?.headers).not.toHaveProperty("Authorization");
    expect(provider).not.toHaveBeenCalled();
    expect(result.contentDisposition).toBe("attachment; filename=\"report.pdf\"");
    expect(new Uint8Array(await result.data.arrayBuffer())).toEqual(new Uint8Array([1, 2, 3]));
  });

  it("sends no body for a link without a password", async () => {
    const fetchMock = stubFetch(() => new Response(new Uint8Array([9])));

    await downloadShare(SHARE_TOKEN, null);

    const init = fetchMock.mock.calls[0]?.[1];
    expect(init?.method).toBe("POST");
    expect(init?.body).toBeUndefined();
  });

  it("surfaces a wrong password and when the next try is allowed", async () => {
    stubFetch(() =>
      jsonResponse(
        { error: { code: "too_many_attempts", message: "Try again later." } },
        { status: 429, headers: { "Retry-After": "300" } },
      ),
    );

    await expect(downloadShare(SHARE_TOKEN, "wrong")).rejects.toMatchObject({
      status: 429,
      code: "too_many_attempts",
      retryAfterSeconds: 300,
    });
  });
});
