import { describe, expect, it } from "vitest";

import { checkCaptureFile, FILE_ACCEPT, uploadLimitBytes } from "./upload";

const MB = 1024 * 1024;

describe("checkCaptureFile", () => {
  it("offers the three capture extensions the server takes to the file picker", () => {
    expect(FILE_ACCEPT).toBe(".pcap,.pcapng,.cap");
  });

  it.each(["sample.pcap", "sample.PCAP", "trace.pcapng", "Trace.PcapNg", "old.cap", "my capture (1).pcap"])(
    "accepts %s",
    (name) => {
      expect(checkCaptureFile({ name, size: 1000 }, 50)).toEqual({ ok: true });
    },
  );

  it.each(["notes.txt", "archive.zip", "capture.pcap.exe", "pcap", "capture"])("rejects %s by its extension", (name) => {
    const result = checkCaptureFile({ name, size: 1000 }, 50);
    expect(result.ok).toBe(false);
    expect(result).toMatchObject({ reason: expect.stringContaining(".pcap, .pcapng or .cap") });
  });

  it("rejects a name that is only an extension", () => {
    expect(checkCaptureFile({ name: ".pcap", size: 1000 }, 50)).toMatchObject({
      ok: false,
      reason: expect.stringContaining("no name before"),
    });
  });

  it("rejects a name too long to send", () => {
    const result = checkCaptureFile({ name: `${"a".repeat(1100)}.pcap`, size: 1000 }, 50);
    expect(result).toMatchObject({ ok: false, reason: expect.stringContaining("too long") });
  });

  it("rejects an empty file", () => {
    expect(checkCaptureFile({ name: "empty.pcap", size: 0 }, 50)).toMatchObject({
      ok: false,
      reason: expect.stringContaining("empty"),
    });
  });

  it("allows a file of exactly the limit and rejects one byte more, naming the size and the limit", () => {
    expect(uploadLimitBytes(50)).toBe(50 * MB);
    expect(checkCaptureFile({ name: "big.pcap", size: 50 * MB }, 50)).toEqual({ ok: true });
    const over = checkCaptureFile({ name: "big.pcap", size: 50 * MB + 1 }, 50);
    expect(over).toMatchObject({ ok: false, reason: expect.stringContaining("50.0 MB, over the 50 MB limit") });
  });

  it("leaves the size to the server when no limit is known", () => {
    expect(checkCaptureFile({ name: "big.pcap", size: 500 * MB }, 0)).toEqual({ ok: true });
  });
});
