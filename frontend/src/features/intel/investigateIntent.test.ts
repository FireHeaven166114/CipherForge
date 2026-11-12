import { describe, expect, it } from "vitest";

import { createIntent, readIntent } from "./investigateIntent";
import { MAX_INDICATOR_LENGTH } from "./limits";

describe("createIntent", () => {
  it("asks for the lookup to start straight away", () => {
    expect(createIntent("8.8.8.8")).toMatchObject({ indicator: "8.8.8.8", autorun: true });
  });

  it("gives every request its own nonce, even for the same indicator", () => {
    expect(createIntent("8.8.8.8").nonce).not.toBe(createIntent("8.8.8.8").nonce);
  });
});

describe("readIntent", () => {
  it("reads back what createIntent made", () => {
    const intent = createIntent("example.com");
    expect(readIntent(intent)).toEqual(intent);
  });

  it("trims the indicator", () => {
    expect(readIntent({ indicator: "  example.com ", autorun: true, nonce: "1" })).toEqual({
      indicator: "example.com",
      autorun: true,
      nonce: "1",
    });
  });

  it.each([
    ["nothing", undefined],
    ["null", null],
    ["a string", "8.8.8.8"],
    ["no indicator", { autorun: true, nonce: "1" }],
    ["an indicator that is not text", { indicator: 8, autorun: true, nonce: "1" }],
    ["an autorun that is not a boolean", { indicator: "8.8.8.8", autorun: "yes", nonce: "1" }],
    ["a nonce that is not text", { indicator: "8.8.8.8", autorun: true, nonce: 1 }],
    ["only spaces", { indicator: "   ", autorun: true, nonce: "1" }],
    ["too long an indicator", { indicator: "a".repeat(MAX_INDICATOR_LENGTH + 1), autorun: true, nonce: "1" }],
  ])("ignores %s, so nothing is looked up from state it did not create", (_name, state) => {
    expect(readIntent(state)).toBeNull();
  });
});
