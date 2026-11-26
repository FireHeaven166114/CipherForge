import { describe, expect, it } from "vitest";

import {
  makeActivityItem,
  makeActivityList,
  makeFileList,
  makeFileStatus,
  makePublicShareInfo,
  makeShare,
  makeShareCreated,
  makeStoredFile,
  makeStoredFileDetail,
} from "../test/filesFixtures";
import {
  isActivityList,
  isFileFeatureStatus,
  isFileList,
  isPublicShareInfo,
  isShare,
  isShareCreated,
  isStoredFile,
  isStoredFileDetail,
} from "./filesGuards";

function without(value: object, key: string): unknown {
  const copy: Record<string, unknown> = { ...(value as Record<string, unknown>) };
  delete copy[key];
  return copy;
}

function expectEveryKeyRequired(guard: (value: unknown) => boolean, valid: object) {
  for (const key of Object.keys(valid)) {
    expect(guard(without(valid, key)), `missing ${key}`).toBe(false);
  }
}

const NOT_OBJECTS = [null, undefined, "text", 42, [], true];

describe("isFileFeatureStatus", () => {
  it("accepts configured and unconfigured status and rejects damaged ones", () => {
    const valid = makeFileStatus();
    expect(isFileFeatureStatus(valid)).toBe(true);
    expect(isFileFeatureStatus(makeFileStatus({ configured: false }))).toBe(true);
    expectEveryKeyRequired(isFileFeatureStatus, valid);
    expect(isFileFeatureStatus({ ...valid, configured: "yes" })).toBe(false);
    expect(isFileFeatureStatus({ ...valid, max_file_size_bytes: -1 })).toBe(false);
    for (const value of NOT_OBJECTS) expect(isFileFeatureStatus(value)).toBe(false);
  });
});

describe("isShare", () => {
  it("accepts every status and nullable timestamps", () => {
    for (const status of ["active", "expired", "revoked", "exhausted"] as const) {
      expect(isShare(makeShare({ status }))).toBe(true);
    }
    expect(
      isShare(
        makeShare({
          status: "revoked",
          revoked_at: "2026-05-20T09:00:00Z",
          last_downloaded_at: "2026-05-20T08:45:00Z",
        }),
      ),
    ).toBe(true);
  });

  it("rejects an unknown status, a bad counter and a missing key", () => {
    const valid = makeShare();
    expect(isShare({ ...valid, status: "paused" })).toBe(false);
    expect(isShare({ ...valid, download_count: -1 })).toBe(false);
    expect(isShare({ ...valid, password_protected: 1 })).toBe(false);
    expectEveryKeyRequired(isShare, valid);
  });
});

describe("isStoredFile, isStoredFileDetail and isFileList", () => {
  it("accepts active and corrupt files", () => {
    expect(isStoredFile(makeStoredFile())).toBe(true);
    expect(isStoredFile(makeStoredFile({ status: "corrupt" }))).toBe(true);
    expect(isStoredFile({ ...makeStoredFile(), status: "deleted" })).toBe(false);
    expectEveryKeyRequired(isStoredFile, makeStoredFile());
  });

  it("a detail needs its list of shares", () => {
    expect(isStoredFileDetail(makeStoredFileDetail({ shares: [makeShare()] }))).toBe(true);
    expect(isStoredFileDetail(makeStoredFile())).toBe(false);
    expect(isStoredFileDetail({ ...makeStoredFileDetail(), shares: [{ id: "x" }] })).toBe(false);
  });

  it("a list needs items and a total", () => {
    expect(isFileList(makeFileList())).toBe(true);
    expect(isFileList(makeFileList([]))).toBe(true);
    expect(isFileList({ items: [], total: -1 })).toBe(false);
    expect(isFileList({ items: [{}], total: 1 })).toBe(false);
    expect(isFileList({ total: 0 })).toBe(false);
  });
});

describe("isShareCreated", () => {
  it("needs the share, the one-time token and the path", () => {
    const valid = makeShareCreated();
    expect(isShareCreated(valid)).toBe(true);
    expectEveryKeyRequired(isShareCreated, valid);
    expect(isShareCreated({ ...valid, token: 12 })).toBe(false);
    expect(isShareCreated({ ...valid, share: {} })).toBe(false);
  });
});

describe("isActivityList", () => {
  it("accepts events with and without a share and reason", () => {
    expect(isActivityList(makeActivityList())).toBe(true);
    expect(isActivityList(makeActivityList([]))).toBe(true);
    expect(
      isActivityList(
        makeActivityList([
          makeActivityItem({ action: "SHARE_DOWNLOAD_REJECTED", share_id: "s-1", reason: "revoked" }),
        ]),
      ),
    ).toBe(true);
    expect(isActivityList({ items: [{ action: "FILE_CREATE" }] })).toBe(false);
    expect(isActivityList({ items: {} })).toBe(false);
  });
});

describe("isPublicShareInfo", () => {
  it("accepts a link with and without its file name", () => {
    expect(isPublicShareInfo(makePublicShareInfo())).toBe(true);
    expect(isPublicShareInfo(makePublicShareInfo({ file_name: null, password_required: true }))).toBe(true);
  });

  it("only understands the 'available' state and rejects damaged answers", () => {
    const valid = makePublicShareInfo();
    expect(isPublicShareInfo({ ...valid, state: "expired" })).toBe(false);
    expectEveryKeyRequired(isPublicShareInfo, valid);
    expect(isPublicShareInfo({ ...valid, downloads_remaining: -1 })).toBe(false);
    expect(isPublicShareInfo({ ...valid, password_required: "no" })).toBe(false);
    for (const value of NOT_OBJECTS) expect(isPublicShareInfo(value)).toBe(false);
  });
});
