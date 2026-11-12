import { act, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { useChartWidth } from "./useChartWidth";

function Probe() {
  const [ref, width] = useChartWidth<HTMLDivElement>(300);
  return (
    <div ref={ref} data-testid="probe">
      {width}
    </div>
  );
}

describe("useChartWidth", () => {
  it("uses the fallback where nothing can be measured", () => {
    render(<Probe />);

    expect(screen.getByTestId("probe")).toHaveTextContent("300");
  });

  it("follows the width the browser reports and ignores an empty measurement", () => {
    let notify: ResizeObserverCallback = () => undefined;
    const disconnect = vi.fn();
    vi.stubGlobal(
      "ResizeObserver",
      class {
        constructor(callback: ResizeObserverCallback) {
          notify = callback;
        }
        observe() {}
        unobserve() {}
        disconnect = disconnect;
      },
    );
    const { unmount } = render(<Probe />);
    const report = (width: number) =>
      act(() => notify([{ contentRect: { width } } as ResizeObserverEntry], {} as ResizeObserver));

    report(412.6);
    expect(screen.getByTestId("probe")).toHaveTextContent("413");

    // A hidden element measures 0; keep the last real width instead of collapsing the chart.
    report(0);
    expect(screen.getByTestId("probe")).toHaveTextContent("413");

    unmount();
    expect(disconnect).toHaveBeenCalled();
  });
});
