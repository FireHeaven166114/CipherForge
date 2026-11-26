import { describe, expect, it } from "vitest";

import {
  attackTechniqueUrl,
  defang,
  malpediaUrl,
  otxPulseUrl,
  threatFoxIocUrl,
  virusTotalUrl,
} from "./links";

describe("otxPulseUrl", () => {
  it("builds the link from a fixed base and a 24-character hex id", () => {
    expect(otxPulseUrl("5f1a2b3c4d5e6f7a8b9c0d1e")).toBe(
      "https://otx.alienvault.com/pulse/5f1a2b3c4d5e6f7a8b9c0d1e",
    );
    expect(otxPulseUrl("5F1A2B3C4D5E6F7A8B9C0D1E")).toBe(
      "https://otx.alienvault.com/pulse/5f1a2b3c4d5e6f7a8b9c0d1e",
    );
  });

  it("never lets provider data choose where a link goes", () => {
    const hostile = [
      "javascript:alert(1)",
      "https://evil.test/",
      "//evil.test",
      "5f1a2b3c4d5e6f7a8b9c0d1e/../../evil",
      "5f1a2b3c4d5e6f7a8b9c0d1e?x=1",
      "5f1a2b3c4d5e6f7a8b9c0d1",
      "zzzzzzzzzzzzzzzzzzzzzzzz",
      "",
      null,
      undefined,
      42,
    ];
    for (const value of hostile) expect(otxPulseUrl(value)).toBeNull();
  });
});

describe("attackTechniqueUrl", () => {
  it("links techniques and sub-techniques in the form ATT&CK uses", () => {
    expect(attackTechniqueUrl("T1566")).toBe("https://attack.mitre.org/techniques/T1566/");
    expect(attackTechniqueUrl("T1059.001")).toBe("https://attack.mitre.org/techniques/T1059/001/");
  });

  it("rejects anything that is not a technique id", () => {
    for (const value of ["t1566", "T156", "T1566.1", "T1566/001", "T1566 ", "javascript:1", null, 7]) {
      expect(attackTechniqueUrl(value)).toBeNull();
    }
  });
});

describe("virusTotalUrl", () => {
  it("rebuilds a report link of VirusTotal's own shape for each kind of object", () => {
    const base = "https://www.virustotal.com/gui";
    expect(virusTotalUrl(`${base}/ip-address/203.0.113.9`)).toBe(`${base}/ip-address/203.0.113.9`);
    expect(virusTotalUrl(`${base}/domain/example.net`)).toBe(`${base}/domain/example.net`);
    expect(virusTotalUrl(`${base}/file/${"a".repeat(64)}`)).toBe(`${base}/file/${"a".repeat(64)}`);
    expect(virusTotalUrl(`${base}/url/${"b".repeat(64)}`)).toBe(`${base}/url/${"b".repeat(64)}`);
    expect(virusTotalUrl(`${base}/ip-address/2606:4700:4700::1111`)).toBe(
      `${base}/ip-address/2606:4700:4700::1111`,
    );
  });

  it("never lets provider data choose where a link goes", () => {
    const hostile = [
      "javascript:alert(1)",
      "http://www.virustotal.com/gui/domain/example.net",
      "https://www.virustotal.com.evil.test/gui/domain/example.net",
      "https://evil.test/gui/domain/example.net",
      "https://www.virustotal.com/gui/domain/example.net/../../evil",
      "https://www.virustotal.com/gui/domain/example.net?x=1",
      "https://www.virustotal.com/gui/domain/example.net#frag",
      "https://www.virustotal.com/gui/domain/",
      "https://www.virustotal.com/gui/user/someone",
      "https://user@www.virustotal.com/gui/domain/example.net",
      "https://www.virustotal.com/gui/domain/exa mple.net",
      "https://www.virustotal.com/gui/domain/example.net\n",
      `https://www.virustotal.com/gui/domain/${"a".repeat(300)}`,
      "//www.virustotal.com/gui/domain/example.net",
      "",
      null,
      undefined,
      42,
    ];
    for (const value of hostile) expect(virusTotalUrl(value)).toBeNull();
  });
});

describe("threatFoxIocUrl", () => {
  it("builds the record link from a fixed base and a numeric record id", () => {
    expect(threatFoxIocUrl("1234567")).toBe("https://threatfox.abuse.ch/ioc/1234567/");
  });

  it("refuses anything but a short run of digits", () => {
    const hostile = [
      "../evil",
      "1234567/../../x",
      "12345678901234",
      "12a",
      "-1",
      "1.5",
      "javascript:1",
      "",
      null,
      undefined,
      1234567,
    ];
    for (const value of hostile) expect(threatFoxIocUrl(value)).toBeNull();
  });
});

describe("malpediaUrl", () => {
  it("rebuilds a Malpedia link of the two shapes ThreatFox gives", () => {
    const base = "https://malpedia.caad.fkie.fraunhofer.de";
    expect(malpediaUrl(`${base}/details/win.examplebot`)).toBe(`${base}/details/win.examplebot`);
    expect(malpediaUrl(`${base}/actor/example_group`)).toBe(`${base}/actor/example_group`);
  });

  it("refuses other hosts, shapes and characters", () => {
    const hostile = [
      "https://evil.test/details/win.examplebot",
      "https://malpedia.caad.fkie.fraunhofer.de.evil.test/details/win.examplebot",
      "http://malpedia.caad.fkie.fraunhofer.de/details/win.examplebot",
      "https://malpedia.caad.fkie.fraunhofer.de/details/Win.Examplebot",
      "https://malpedia.caad.fkie.fraunhofer.de/details/win.examplebot/",
      "https://malpedia.caad.fkie.fraunhofer.de/details/win.examplebot?x=1",
      "https://malpedia.caad.fkie.fraunhofer.de/library/win.examplebot",
      "https://malpedia.caad.fkie.fraunhofer.de/details/../x",
      "javascript:alert(1)",
      "",
      null,
      undefined,
      7,
    ];
    for (const value of hostile) expect(malpediaUrl(value)).toBeNull();
  });
});

describe("defang", () => {
  it("writes a web address so that it cannot be followed by accident", () => {
    expect(defang("https://reports.example.test/a?b=1")).toBe("hxxps://reports.example.test/a?b=1");
    expect(defang("http://reports.example.test/")).toBe("hxxp://reports.example.test/");
    expect(defang("HTTPS://Reports.Example.test/")).toBe("hxxpS://Reports.Example.test/");
  });

  it("leaves text that is not a web address as it was", () => {
    expect(defang("javascript:alert(1)")).toBe("javascript:alert(1)");
    expect(defang("a report from http://later.test")).toBe("a report from http://later.test");
    expect(defang("")).toBe("");
  });
});
