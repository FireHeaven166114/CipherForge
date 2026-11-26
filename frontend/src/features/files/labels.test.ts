import { describe, expect, it } from "vitest";

import { FILE_STATES, SHARE_STATUSES } from "../../types/files";
import {
  actionLabel,
  describeLinks,
  FILE_STATE_META,
  reasonLabel,
  resultMeta,
  SHARE_STATUS_META,
  shortId,
} from "./labels";

describe("SHARE_STATUS_META", () => {
  it("gives every share status its own word, so colour never carries the meaning alone", () => {
    const labels = SHARE_STATUSES.map((status) => SHARE_STATUS_META[status].label);
    expect(new Set(labels).size).toBe(SHARE_STATUSES.length);
    expect(labels).not.toContain("");
  });

  it("colours only a working link as good", () => {
    expect(SHARE_STATUS_META.active.tone).toBe("ok");
    expect(SHARE_STATUS_META.revoked.tone).toBe("bad");
    expect(SHARE_STATUS_META.expired.tone).toBe("warn");
    expect(SHARE_STATUS_META.exhausted.tone).toBe("warn");
  });
});

describe("FILE_STATE_META", () => {
  it("names a file that failed its integrity check as a problem", () => {
    for (const state of FILE_STATES) expect(FILE_STATE_META[state].label).not.toBe("");
    expect(FILE_STATE_META.active.tone).toBe("ok");
    expect(FILE_STATE_META.corrupt).toEqual({ label: "Integrity problem", tone: "bad" });
  });
});

describe("actionLabel", () => {
  it.each([
    ["FILE_CREATE", "File uploaded"],
    ["SHARE_CREATE", "Link created"],
    ["SHARE_DOWNLOAD", "File downloaded"],
    ["SHARE_DOWNLOAD_REJECTED", "Download refused"],
    ["SHARE_PASSWORD_FAILED", "Wrong password"],
    ["SHARE_EXPIRED", "Expired link opened"],
    ["SHARE_REVOKE", "Link revoked"],
    ["SHARE_LIMIT_REACHED", "Download limit reached"],
    ["FILE_INTEGRITY_FAILED", "Integrity check failed"],
    ["FILE_DELETE", "File deleted"],
  ])("calls %s %s", (action, label) => {
    expect(actionLabel(action)).toBe(label);
  });

  it("shows an action it does not know as the API sent it, even one named like a JavaScript property", () => {
    expect(actionLabel("SOMETHING_NEW")).toBe("SOMETHING_NEW");
    expect(actionLabel("constructor")).toBe("constructor");
    expect(actionLabel("__proto__")).toBe("__proto__");
    expect(actionLabel("toString")).toBe("toString");
  });
});

describe("resultMeta", () => {
  it("pairs every known result with a word and a tone", () => {
    expect(resultMeta("success")).toEqual({ label: "Success", tone: "ok" });
    expect(resultMeta("rejected")).toEqual({ label: "Rejected", tone: "warn" });
    expect(resultMeta("partial")).toEqual({ label: "Partial", tone: "warn" });
    expect(resultMeta("failed")).toEqual({ label: "Failed", tone: "bad" });
  });

  it("shows an unknown result as it was sent, in a neutral tone", () => {
    expect(resultMeta("queued")).toEqual({ label: "queued", tone: "neutral" });
    expect(resultMeta("")).toEqual({ label: "Unknown", tone: "neutral" });
    expect(resultMeta("constructor")).toEqual({ label: "constructor", tone: "neutral" });
  });
});

describe("reasonLabel", () => {
  it("returns null when there is no reason", () => {
    expect(reasonLabel(null)).toBeNull();
    expect(reasonLabel("")).toBeNull();
  });

  it("explains the reasons the API gives and passes on any other", () => {
    expect(reasonLabel("revoked")).toBe("The link had been revoked");
    expect(reasonLabel("invalid_password")).toBe("The password was wrong");
    expect(reasonLabel("limit_reached")).toBe("The download limit was used up");
    expect(reasonLabel("something_new")).toBe("something_new");
  });
});

describe("shortId", () => {
  it("keeps the first eight characters", () => {
    expect(shortId("c3d4e5f6-a7b8-4c9d-8e1f-2a3b4c5d6e7f")).toBe("c3d4e5f6");
    expect(shortId("abc")).toBe("abc");
  });
});

describe("describeLinks", () => {
  it("says how many of a file's links still work", () => {
    expect(describeLinks({ share_count: 0, active_share_count: 0 })).toBe("No links");
    expect(describeLinks({ share_count: 1, active_share_count: 1 })).toBe("1 active of 1 link");
    expect(describeLinks({ share_count: 3, active_share_count: 0 })).toBe("0 active of 3 links");
  });
});
