import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { useShareCountdown } from "./useShareCountdown";

describe("useShareCountdown", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("is zero without a deadline", () => {
    const { result } = renderHook(() => useShareCountdown(null));
    expect(result.current).toBe(0);
  });

  it("counts whole seconds down to zero and then stops ticking", async () => {
    const deadline = Date.now() + 3000;
    const { result } = renderHook(() => useShareCountdown(deadline));
    expect(result.current).toBe(3);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
    });
    expect(result.current).toBe(2);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(2000);
    });
    expect(result.current).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("is already zero for a deadline in the past", () => {
    const { result } = renderHook(() => useShareCountdown(Date.now() - 5000));
    expect(result.current).toBe(0);
  });

  it("starts over for a new deadline and leaves no timer behind when the screen goes", async () => {
    const { result, rerender, unmount } = renderHook(
      ({ deadline }: { deadline: number | null }) => useShareCountdown(deadline),
      { initialProps: { deadline: Date.now() + 2000 } },
    );
    expect(result.current).toBe(2);

    rerender({ deadline: Date.now() + 9000 });
    expect(result.current).toBe(9);

    unmount();
    expect(vi.getTimerCount()).toBe(0);
  });
});
