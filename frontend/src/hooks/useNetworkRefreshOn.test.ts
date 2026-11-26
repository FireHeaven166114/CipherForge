import { renderHook } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { useNetworkRefreshOn } from "./useNetworkRefreshOn";

describe("useNetworkRefreshOn", () => {
  it("does nothing on the first render, because the data is being loaded then anyway", () => {
    const refresh = vi.fn();
    renderHook(() => useNetworkRefreshOn(1, refresh));
    expect(refresh).not.toHaveBeenCalled();
  });

  it("asks once each time the trigger changes, and not when it stays the same", () => {
    const refresh = vi.fn();
    const { rerender } = renderHook(({ trigger }) => useNetworkRefreshOn(trigger, refresh), {
      initialProps: { trigger: "running:0" },
    });

    rerender({ trigger: "running:0" });
    expect(refresh).not.toHaveBeenCalled();

    rerender({ trigger: "running:3" });
    expect(refresh).toHaveBeenCalledTimes(1);

    rerender({ trigger: "running:3" });
    rerender({ trigger: "completed:3" });
    expect(refresh).toHaveBeenCalledTimes(2);
  });

  it("uses the newest refresh function and does not ask again just because it changed", () => {
    const first = vi.fn();
    const second = vi.fn();
    const { rerender } = renderHook(({ refresh }) => useNetworkRefreshOn(0, refresh), {
      initialProps: { refresh: first },
    });

    rerender({ refresh: second });

    expect(first).not.toHaveBeenCalled();
    expect(second).not.toHaveBeenCalled();
  });
});
