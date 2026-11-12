import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import DotMap, { type MapMarker } from "./DotMap";
import GaugeRing from "./GaugeRing";

describe("GaugeRing", () => {
  it("shows the score with its risk band in words", () => {
    render(<GaugeRing score={80} band="high" />);

    expect(screen.getByText("Risk score")).toBeInTheDocument();
    expect(screen.getByText("80")).toBeInTheDocument();
    expect(screen.getByText("High")).toBeInTheDocument();
  });

  it("shows 'Not assessed' instead of a clean-looking zero when there is no verdict", () => {
    const { container } = render(<GaugeRing score={null} band={null} />);

    expect(screen.getByText("Not assessed")).toBeInTheDocument();
    expect(screen.queryByText("0")).not.toBeInTheDocument();
    expect(container.querySelector(".animate-gauge")).toBeNull();
  });

  it("does not draw an arc for a score of zero that was assessed", () => {
    const { container } = render(<GaugeRing score={0} band="informational" />);

    expect(screen.getByText("Informational")).toBeInTheDocument();
    expect(container.querySelector(".animate-gauge")).toBeNull();
  });
});

const MARKERS: MapMarker[] = [
  { code: "NL", name: "Netherlands", count: 4, maxRisk: 80 },
  { code: "US", name: "United States", count: 1, maxRisk: 10 },
  { code: "QQ", name: "QQ", count: 2, maxRisk: 30 },
];

describe("DotMap", () => {
  function renderMap(onSelect = vi.fn(), selected: string | null = null) {
    render(<DotMap markers={MARKERS} selected={selected} onSelect={onSelect} noun="indicator" label="Provider-reported countries" />);
    return onSelect;
  }

  it("puts a button on every country it can place, named with count and risk", () => {
    renderMap();

    expect(screen.getByRole("group", { name: "Provider-reported countries" })).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Netherlands: 4 indicators, highest risk High" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "United States: 1 indicator, highest risk Informational" }),
    ).toBeInTheDocument();
    expect(screen.getAllByRole("button")).toHaveLength(2);
  });

  it("says which countries it could not place, without dropping them silently", () => {
    renderMap();

    expect(screen.getByText(/1 country has no position on this map/)).toBeInTheDocument();
  });

  it("opens a country on click, Enter or Space", async () => {
    const user = userEvent.setup();
    const onSelect = renderMap();
    const netherlands = screen.getByRole("button", { name: /Netherlands/ });

    await user.click(netherlands);
    expect(onSelect).toHaveBeenLastCalledWith("NL");

    onSelect.mockClear();
    netherlands.focus();
    await user.keyboard("{Enter}");
    await user.keyboard(" ");
    expect(onSelect).toHaveBeenCalledTimes(2);
    expect(onSelect).toHaveBeenCalledWith("NL");
  });

  it("calls the position provider-reported, never the attacker's location", () => {
    const { container } = render(
      <DotMap markers={MARKERS} selected={null} onSelect={() => undefined} noun="indicator" label="Map" />,
    );

    expect(container.querySelector("title")?.textContent).toContain("provider-reported country");
  });
});
