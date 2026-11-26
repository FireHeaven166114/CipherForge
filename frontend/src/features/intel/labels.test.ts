import { describe, expect, it } from "vitest";

import { makeFailedProvider, makeVirusTotal } from "../../test/fixtures";
import { PROVIDER_REASONS, PROVIDER_VERDICTS } from "../../types/intel";
import { PROVIDER_REASON_META, PROVIDER_VERDICT_META, canRetry } from "./labels";

describe("PROVIDER_VERDICT_META", () => {
  it("describes every verdict a provider can give", () => {
    for (const verdict of PROVIDER_VERDICTS) {
      const meta = PROVIDER_VERDICT_META[verdict];
      expect(meta.label).not.toBe("");
      expect(meta.explanation).not.toBe("");
    }
  });

  it("never shows a result as safe: only a harmful verdict is coloured as a problem", () => {
    expect(PROVIDER_VERDICT_META.malicious.tone).toBe("bad");
    expect(PROVIDER_VERDICT_META.suspicious.tone).toBe("warn");
    for (const verdict of ["harmless", "unknown", "not_found"] as const) {
      expect(PROVIDER_VERDICT_META[verdict].tone).toBe("neutral");
    }
    for (const verdict of ["harmless", "not_found"] as const) {
      expect(PROVIDER_VERDICT_META[verdict].explanation).toMatch(/not proof that the indicator is safe/);
    }
  });
});

describe("PROVIDER_REASON_META", () => {
  it("describes every reason a lookup can fail", () => {
    for (const reason of PROVIDER_REASONS) {
      const meta = PROVIDER_REASON_META[reason];
      expect(meta.label).not.toBe("");
      expect(meta.explanation).not.toBe("");
    }
  });
});

describe("canRetry", () => {
  it("offers a retry only for failures that asking again could fix", () => {
    const retryable = ["rate_limited", "timeout", "unavailable", "malformed_response"] as const;
    const permanent = ["not_configured", "invalid_input", "auth_failed"] as const;

    for (const reason of retryable) {
      expect(canRetry(makeFailedProvider("virustotal", "VirusTotal", "error", reason, "x"))).toBe(true);
    }
    for (const reason of permanent) {
      expect(canRetry(makeFailedProvider("virustotal", "VirusTotal", "error", reason, "x"))).toBe(false);
    }
  });

  it("offers nothing for a provider that answered", () => {
    expect(canRetry(makeVirusTotal())).toBe(false);
  });
});
