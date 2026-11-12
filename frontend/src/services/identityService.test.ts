import { describe, expect, it } from "vitest";

import { jsonResponse, stubFetch } from "../test/http";
import { fetchMe } from "./identityService";

describe("fetchMe", () => {
  it("returns the caller's roles and sign-in mode", async () => {
    const me = { subject: "dev-user", name: null, roles: ["analyst"], auth_mode: "dev" };
    const fetchMock = stubFetch(() => jsonResponse(me));

    await expect(fetchMe()).resolves.toEqual(me);
    expect(fetchMock.mock.calls[0]?.[0]).toBe("/api/v1/me");
  });

  it("rejects an unknown sign-in mode or a malformed role list", async () => {
    stubFetch(() => jsonResponse({ subject: "x", name: null, roles: [], auth_mode: "magic" }));
    await expect(fetchMe()).rejects.toMatchObject({ code: "invalid_response" });

    stubFetch(() => jsonResponse({ subject: "x", name: null, roles: [1], auth_mode: "dev" }));
    await expect(fetchMe()).rejects.toMatchObject({ code: "invalid_response" });
  });
});
