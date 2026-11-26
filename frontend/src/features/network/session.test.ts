import { describe, expect, it } from "vitest";

import { parseSessionParam, resolveSessionId } from "./session";

const ID = "7c1e5b2a-4f3d-4e8a-9b6c-2d1f0a9e8b7c";
const OTHER = "0d4c3b2a-9e8f-4a7b-8c6d-5e4f3a2b1c0d";

describe("parseSessionParam", () => {
  it("accepts a session id, whatever its case", () => {
    expect(parseSessionParam(ID)).toBe(ID);
    expect(parseSessionParam(ID.toUpperCase())).toBe(ID);
  });

  it.each([null, "", "latest", "7c1e5b2a", `${ID}x`, ` ${ID}`, "../sessions", `${ID}/flows`])(
    "ignores %j",
    (value) => {
      expect(parseSessionParam(value)).toBeNull();
    },
  );
});

describe("resolveSessionId", () => {
  it("prefers the one asked for over the live one, and has none when there is neither", () => {
    expect(resolveSessionId(ID, OTHER)).toBe(ID);
    expect(resolveSessionId(null, OTHER)).toBe(OTHER);
    expect(resolveSessionId(ID, null)).toBe(ID);
    expect(resolveSessionId(null, null)).toBeNull();
  });
});
