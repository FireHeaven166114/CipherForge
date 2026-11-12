import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import BarMeter from "./BarMeter";

function fillWidth(container: HTMLElement): string | null {
  return container.querySelectorAll("rect")[1]?.getAttribute("width") ?? null;
}

describe("BarMeter", () => {
  it("draws a visible sliver for a small share but nothing for zero", () => {
    expect(fillWidth(render(<BarMeter percent={0.4} fillClass="fill-cipher" />).container)).toBe(
      "2",
    );
    expect(fillWidth(render(<BarMeter percent={0} fillClass="fill-cipher" />).container)).toBe(
      "0",
    );
  });

  it("keeps out-of-range and invalid values inside the bar", () => {
    expect(fillWidth(render(<BarMeter percent={250} fillClass="fill-cipher" />).container)).toBe(
      "100",
    );
    expect(
      fillWidth(render(<BarMeter percent={Number.NaN} fillClass="fill-cipher" />).container),
    ).toBe("0");
  });

  it("is hidden from assistive technology, because the value is printed as text", () => {
    const { container } = render(<BarMeter percent={50} fillClass="fill-cipher" />);

    expect(container.querySelector("svg")).toHaveAttribute("aria-hidden", "true");
  });
});
