import { describe, expect, it } from "vitest";

import { makeBackend, makeInterface, makeNetworkStatus } from "../../test/networkFixtures";
import type { CaptureState } from "../../types/network";
import {
  activeInterfaceId,
  captureNotices,
  interfaceLabel,
  startAvailability,
  stopAvailability,
} from "./capture";

describe("captureNotices", () => {
  it("says nothing when the state badge says it all", () => {
    expect(captureNotices(makeNetworkStatus({ state: "ready" }))).toEqual([]);
    expect(captureNotices(makeNetworkStatus({ state: "running", interface: "eth0" }))).toEqual([]);
    expect(captureNotices(makeNetworkStatus({ state: "starting" }))).toEqual([]);
  });

  it("explains a permission refusal: the operating system, the account, the platform, the guide", () => {
    const [notice] = captureNotices(makeNetworkStatus({ state: "permission_denied" }));
    expect(notice?.tone).toBe("bad");
    expect(notice?.body).toContain("operating system refused packet capture");
    expect(notice?.body).toContain("account that runs the CipherForge API");
    expect(notice?.body).toContain("differ by platform");
    expect(notice?.body).toContain("docs/network-monitoring.md");
  });

  it("explains a missing capture library and says analysis may still work", () => {
    const [notice] = captureNotices(
      makeNetworkStatus({ state: "not_configured", backend: makeBackend({ name: "none", available: false }) }),
    );
    expect(notice?.tone).toBe("warn");
    expect(notice?.body).toContain("Npcap");
    expect(notice?.body).toContain("libpcap");
    expect(notice?.body).toContain("PCAP file may still work");
  });

  it("shows the message of a failed capture, else the wording for its code", () => {
    const [shown] = captureNotices(makeNetworkStatus({ state: "failed", message: "The adapter went away." }));
    expect(shown?.body).toBe("The adapter went away.");
    const [coded] = captureNotices(
      makeNetworkStatus({ state: "failed", message: null, error_code: "interface_unavailable" }),
    );
    expect(coded?.body).toContain("disconnected or disabled");
    const [plain] = captureNotices(makeNetworkStatus({ state: "failed", message: null, error_code: null }));
    expect(plain?.body).toContain("stopped because of an error");
  });

  it("notes that a stopped capture keeps its results", () => {
    const [notice] = captureNotices(makeNetworkStatus({ state: "stopped" }));
    expect(notice).toMatchObject({ tone: "info", title: "Capture stopped" });
  });

  it("explains that someone else's capture holds the single slot, besides any state notice", () => {
    expect(captureNotices(makeNetworkStatus({ busy: true })).map((notice) => notice.title)).toEqual([
      "Another capture is running",
    ]);
    expect(
      captureNotices(makeNetworkStatus({ busy: true, state: "stopped" })).map((notice) => notice.title),
    ).toEqual(["Capture stopped", "Another capture is running"]);
  });
});

describe("startAvailability", () => {
  const ready = makeNetworkStatus();

  it("allows a start on a ready server with an interface chosen", () => {
    expect(startAvailability(ready, "eth0", 2)).toEqual({ allowed: true, reason: null });
  });

  it.each<[string, Parameters<typeof startAvailability>, string]>([
    [
      "no backend",
      [
        makeNetworkStatus({ state: "not_configured", backend: makeBackend({ available: false }) }),
        "eth0",
        1,
      ],
      "not available",
    ],
    ["a capture under way", [makeNetworkStatus({ state: "running" }), "eth0", 1], "already running"],
    ["someone else's capture", [makeNetworkStatus({ busy: true }), "eth0", 1], "single capture slot"],
    ["no interfaces", [ready, null, 0], "no interface"],
    ["no choice", [ready, "", 2], "Choose an interface"],
  ])("refuses with %s and says why", (_name, args, reason) => {
    const result = startAvailability(...args);
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain(reason);
  });
});

describe("stopAvailability", () => {
  it.each<[CaptureState, boolean]>([
    ["running", true],
    ["starting", true],
    ["stopping", false],
    ["ready", false],
    ["stopped", false],
    ["failed", false],
  ])("in state %s, stopping is allowed: %s", (state, allowed) => {
    const result = stopAvailability(makeNetworkStatus({ state }));
    expect(result.allowed).toBe(allowed);
    expect(result.reason === null).toBe(allowed);
  });
});

describe("interfaceLabel", () => {
  it("joins the name and the description, once", () => {
    expect(interfaceLabel({ name: "eth0", description: "Ethernet adapter" })).toBe("eth0 - Ethernet adapter");
    expect(interfaceLabel({ name: "lo", description: "" })).toBe("lo");
    expect(interfaceLabel({ name: "lo", description: "  " })).toBe("lo");
    expect(interfaceLabel({ name: "lo", description: "lo" })).toBe("lo");
  });
});

describe("activeInterfaceId", () => {
  const interfaces = [makeInterface({ id: "{GUID-1}", name: "Ethernet" }), makeInterface({ id: "lo", name: "lo" })];

  it("finds the interface of a running capture by id or by name", () => {
    expect(activeInterfaceId({ interface: "Ethernet" }, interfaces)).toBe("{GUID-1}");
    expect(activeInterfaceId({ interface: "lo" }, interfaces)).toBe("lo");
  });

  it("finds none when there is no capture or the interface is gone", () => {
    expect(activeInterfaceId({ interface: null }, interfaces)).toBeNull();
    expect(activeInterfaceId({ interface: "wlan9" }, interfaces)).toBeNull();
  });
});
