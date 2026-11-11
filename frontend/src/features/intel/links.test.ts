import { describe, expect, it } from "vitest";

import { attackTechniqueUrl, otxPulseUrl } from "./links";

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
