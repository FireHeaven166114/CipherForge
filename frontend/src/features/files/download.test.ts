import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { stubBlobDownload } from "../../test/filesFixtures";
import { REVOKE_DELAY_MS, saveBlob } from "./download";

describe("saveBlob", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("offers the blob under the given name through a temporary anchor", () => {
    const stub = stubBlobDownload();
    const blob = new Blob(["hello"]);

    saveBlob(blob, "report.pdf");

    expect(stub.createObjectURL).toHaveBeenCalledWith(blob);
    expect(stub.clicks).toEqual([{ download: "report.pdf", href: "blob:cipherforge-test" }]);
    expect(document.querySelector("a[download]")).toBeNull();
  });

  it("keeps the object URL until the browser has had time to read it, then revokes it once", () => {
    const stub = stubBlobDownload();

    saveBlob(new Blob(["x"]), "a.txt");
    expect(stub.revokeObjectURL).not.toHaveBeenCalled();

    vi.advanceTimersByTime(REVOKE_DELAY_MS - 1);
    expect(stub.revokeObjectURL).not.toHaveBeenCalled();

    vi.advanceTimersByTime(1);
    expect(stub.revokeObjectURL).toHaveBeenCalledTimes(1);
    expect(stub.revokeObjectURL).toHaveBeenCalledWith("blob:cipherforge-test");
  });

  it("never lets a name pick a different folder or an unsafe file name", () => {
    const stub = stubBlobDownload();

    saveBlob(new Blob(["x"]), String.raw`..\..\evil.exe`);
    saveBlob(new Blob(["x"]), "..");

    expect(stub.clicks.map((click) => click.download)).toEqual(["evil.exe", "download"]);
  });

  it("removes the anchor and still revokes the URL when the click fails", () => {
    const stub = stubBlobDownload();
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {
      throw new Error("blocked");
    });

    expect(() => saveBlob(new Blob(["x"]), "a.txt")).toThrow("blocked");
    expect(document.querySelector("a[download]")).toBeNull();

    vi.advanceTimersByTime(REVOKE_DELAY_MS);
    expect(stub.revokeObjectURL).toHaveBeenCalledTimes(1);
  });
});
