import { describe, expect, it } from "vitest";

import { jsonResponse, stubFetch } from "../test/http";
import { fetchHealth, fetchReadiness } from "./healthService";

describe("fetchHealth", () => {
  it("returns the liveness payload", async () => {
    stubFetch(() => jsonResponse({ status: "ok", service: "cipherforge-api", version: "0.1.0" }));

    await expect(fetchHealth()).resolves.toEqual({
      status: "ok",
      service: "cipherforge-api",
      version: "0.1.0",
    });
  });

  it("rejects a payload of the wrong shape", async () => {
    stubFetch(() => jsonResponse({ status: "ok" }));

    await expect(fetchHealth()).rejects.toMatchObject({ code: "invalid_response" });
  });
});

describe("fetchReadiness", () => {
  it("treats a 503 with a readiness body as a result", async () => {
    const body = { status: "not_ready", checks: { database: "unavailable" } };
    stubFetch(() => jsonResponse(body, { status: 503 }));

    await expect(fetchReadiness()).resolves.toEqual(body);
  });

  it("rejects unknown check values", async () => {
    stubFetch(() => jsonResponse({ status: "ready", checks: { database: "maybe" } }));

    await expect(fetchReadiness()).rejects.toMatchObject({ code: "invalid_response" });
  });
});
