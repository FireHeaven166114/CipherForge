import { describe, expect, it } from "vitest";

import { guessIndicatorType } from "./guess";

describe("guessIndicatorType", () => {
  it.each([
    ["8.8.8.8", "ipv4"],
    ["  203.0.113.9  ", "ipv4"],
    ["2001:4860:4860::8888", "ipv6"],
    ["::1", "ipv6"],
    ["::ffff:192.0.2.1", "ipv6"],
    ["example.com", "domain"],
    ["login.Example-Test.co.uk", "domain"],
    ["https://example.com/path?x=1", "url"],
    ["HTTP://Example.com", "url"],
    ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256"],
    ["E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", "sha256"],
  ])("recognises %s as %s", (text, type) => {
    expect(guessIndicatorType(text)).toBe(type);
  });

  it.each([
    "",
    "   ",
    "999.1.1.1",
    "1.2.3",
    "localhost",
    "not an indicator",
    "a:b:c",
    "1:2",
    "http://",
    "ftp://example.com",
    "javascript:alert(1)",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85",
    "-bad.example.com",
  ])("does not guess for %j", (text) => {
    expect(guessIndicatorType(text)).toBeNull();
  });
});
