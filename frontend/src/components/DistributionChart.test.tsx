import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import BarMeter from "./BarMeter";
import DistributionChart from "./DistributionChart";

function fillWidth(container: HTMLElement): string | null {
  return container.querySelectorAll("rect")[1]?.getAttribute("width") ?? null;
}

describe("BarMeter", () => {
  it("draws a visible sliver for a small share but nothing for zero", () => {
    expect(fillWidth(render(<BarMeter percent={0.4} fillClass="fill-cyan-500" />).container)).toBe(
      "2",
    );
    expect(fillWidth(render(<BarMeter percent={0} fillClass="fill-cyan-500" />).container)).toBe(
      "0",
    );
  });

  it("keeps out-of-range and invalid values inside the bar", () => {
    expect(fillWidth(render(<BarMeter percent={250} fillClass="fill-cyan-500" />).container)).toBe(
      "100",
    );
    expect(fillWidth(render(<BarMeter percent={Number.NaN} fillClass="fill-cyan-500" />).container)).toBe(
      "0",
    );
  });

  it("is hidden from assistive technology, because the value is printed as text", () => {
    const { container } = render(<BarMeter percent={50} fillClass="fill-cyan-500" />);

    expect(container.querySelector("svg")).toHaveAttribute("aria-hidden", "true");
  });
});

describe("DistributionChart", () => {
  const high = { id: "high", label: "High", marker: "▲", count: 3, fillClass: "fill-orange-500" };
  const low = { id: "low", label: "Low", marker: "●", count: 1, fillClass: "fill-yellow-500" };

  it("prints every count and share as text beside its bar", () => {
    render(<DistributionChart rows={[high, low]} total={4} />);

    const items = screen.getAllByRole("listitem");
    expect(items).toHaveLength(2);
    expect(within(items[0] as HTMLElement).getByText("High")).toBeInTheDocument();
    expect(items[0]).toHaveTextContent("3 (75%)");
    expect(items[1]).toHaveTextContent("1 (25%)");
  });

  it("shows zero shares rather than NaN when there is nothing to divide", () => {
    render(<DistributionChart rows={[{ ...high, count: 0 }]} total={0} />);

    expect(screen.getByRole("listitem")).toHaveTextContent("0 (0%)");
  });
});
