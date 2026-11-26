import { afterEach, describe, expect, it } from "vitest";

import { jsonResponse, stubFetch } from "../test/http";
import {
  FILE_ID,
  SHARE_ID,
  makeActivityList,
  makeFileList,
  makeFileStatus,
  makeShare,
  makeShareCreated,
  makeStoredFile,
  makeStoredFileDetail,
} from "../test/filesFixtures";
import { setTokenProvider } from "./apiClient";
import {
  createShare,
  deleteStoredFile,
  getFileActivity,
  getFileStatus,
  getStoredFile,
  listFiles,
  revokeShare,
  uploadStoredFile,
} from "./filesService";

afterEach(() => {
  setTokenProvider(null);
});

function firstCall(fetchMock: ReturnType<typeof stubFetch>): [string, RequestInit | undefined] {
  const call = fetchMock.mock.calls[0];
  if (!call) throw new Error("fetch was not called");
  return [String(call[0]), call[1]];
}

describe("reading", () => {
  it("asks for the feature status with the signed-in token", async () => {
    const status = makeFileStatus();
    const fetchMock = stubFetch(() => jsonResponse(status));
    setTokenProvider(() => "token-1");

    await expect(getFileStatus()).resolves.toEqual(status);

    const [url, init] = firstCall(fetchMock);
    expect(url).toBe("/api/v1/files/status");
    expect(init?.headers).toMatchObject({ Authorization: "Bearer token-1" });
  });

  it("adds paging to the file list only when it was given", async () => {
    const fetchMock = stubFetch(() => jsonResponse(makeFileList()));

    await listFiles();
    await listFiles({ limit: 25, offset: 50 });

    expect(fetchMock.mock.calls.map((call) => String(call[0]))).toEqual([
      "/api/v1/files",
      "/api/v1/files?limit=25&offset=50",
    ]);
  });

  it("encodes a file id so it can never change the path", async () => {
    const fetchMock = stubFetch(() => jsonResponse(makeStoredFileDetail()));

    await getStoredFile("../status?x=1");

    expect(firstCall(fetchMock)[0]).toBe("/api/v1/files/..%2Fstatus%3Fx%3D1");
  });

  it("reads the activity of one file", async () => {
    const fetchMock = stubFetch(() => jsonResponse(makeActivityList()));

    await getFileActivity(FILE_ID);

    expect(firstCall(fetchMock)[0]).toBe(`/api/v1/files/${FILE_ID}/activity`);
  });

  it("reports an answer of the wrong shape as invalid", async () => {
    stubFetch(() => jsonResponse({ items: "none", total: 0 }));

    await expect(listFiles()).rejects.toMatchObject({ code: "invalid_response" });
  });
});

describe("uploading", () => {
  it("sends the raw bytes as octet-stream with the name percent-encoded", async () => {
    const stored = makeStoredFile();
    const fetchMock = stubFetch(() => jsonResponse(stored, { status: 201 }));
    const file = new File(["secret report"], "Q3 résumé #1.pdf");

    await expect(uploadStoredFile(file)).resolves.toEqual(stored);

    const [url, init] = firstCall(fetchMock);
    expect(url).toBe("/api/v1/files");
    expect(init?.method).toBe("POST");
    expect(init?.body).toBe(file);
    expect(init?.headers).toMatchObject({
      "Content-Type": "application/octet-stream",
      "X-File-Name": encodeURIComponent("Q3 résumé #1.pdf"),
    });
  });

  it("surfaces the server's reason when a file is refused", async () => {
    stubFetch(() =>
      jsonResponse(
        { error: { code: "file_too_large", message: "The file is larger than the allowed size." } },
        { status: 413 },
      ),
    );

    await expect(uploadStoredFile(new File(["x"], "a.bin"))).rejects.toMatchObject({
      status: 413,
      code: "file_too_large",
    });
  });
});

describe("links", () => {
  it("creates a link with the chosen limits and a password in the body only", async () => {
    const created = makeShareCreated();
    const fetchMock = stubFetch(() => jsonResponse(created, { status: 201 }));

    await expect(
      createShare(FILE_ID, { expires_in_hours: 2, max_downloads: 3, password: "correct horse" }),
    ).resolves.toEqual(created);

    const [url, init] = firstCall(fetchMock);
    expect(url).toBe(`/api/v1/files/${FILE_ID}/shares`);
    expect(url).not.toContain("correct");
    expect(init?.method).toBe("POST");
    expect(init?.body).toBe(
      JSON.stringify({ expires_in_hours: 2, max_downloads: 3, password: "correct horse" }),
    );
  });

  it("revokes one link of one file with a POST that has no body", async () => {
    const share = makeShare({ status: "revoked" });
    const fetchMock = stubFetch(() => jsonResponse(share));

    await expect(revokeShare(FILE_ID, SHARE_ID)).resolves.toEqual(share);

    const [url, init] = firstCall(fetchMock);
    expect(url).toBe(`/api/v1/files/${FILE_ID}/shares/${SHARE_ID}/revoke`);
    expect(init?.method).toBe("POST");
    expect(init?.body).toBeUndefined();
  });

  it("refuses a created link that does not carry its token", async () => {
    stubFetch(() => jsonResponse({ share: makeShare(), path: "/share/x" }, { status: 201 }));

    await expect(createShare(FILE_ID, {})).rejects.toMatchObject({ code: "invalid_response" });
  });
});

describe("deleting", () => {
  it("deletes a file with a DELETE that has no body and resolves on 204", async () => {
    const fetchMock = stubFetch(() => new Response(null, { status: 204 }));

    await expect(deleteStoredFile(FILE_ID)).resolves.toBeUndefined();

    const [url, init] = firstCall(fetchMock);
    expect(url).toBe(`/api/v1/files/${FILE_ID}`);
    expect(init?.method).toBe("DELETE");
    expect(init?.body).toBeUndefined();
  });

  it("reports a file that is not the caller's as not found", async () => {
    stubFetch(() =>
      jsonResponse({ error: { code: "file_not_found", message: "File not found." } }, { status: 404 }),
    );

    await expect(deleteStoredFile(FILE_ID)).rejects.toMatchObject({
      status: 404,
      code: "file_not_found",
    });
  });
});
