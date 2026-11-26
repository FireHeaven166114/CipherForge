import { renderHook } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { useShareNoIndex } from "./useShareNoIndex";

function robots() {
  return document.head.querySelectorAll('meta[name="robots"]');
}

describe("useShareNoIndex", () => {
  it("asks search engines to skip the page while it is open and stops asking when it closes", () => {
    expect(robots()).toHaveLength(0);

    const { unmount } = renderHook(() => useShareNoIndex());
    expect(robots()).toHaveLength(1);
    expect(robots()[0]).toHaveAttribute("content", "noindex,nofollow");

    unmount();
    expect(robots()).toHaveLength(0);
  });

  it("leaves a tag that was there before alone", () => {
    const existing = document.createElement("meta");
    existing.name = "robots";
    existing.content = "index";
    document.head.append(existing);

    const { unmount } = renderHook(() => useShareNoIndex());
    expect(robots()).toHaveLength(2);
    unmount();
    expect(robots()).toHaveLength(1);
    expect(robots()[0]).toBe(existing);

    existing.remove();
  });
});
