import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";

import { svgOf } from "../../test/svg";
import Donut, { type DonutSlice } from "./Donut";

const SLICES: DonutSlice[] = [
  {
    key: "critical",
    label: "Critical",
    value: 1,
    stroke: "stroke-crit",
    swatch: "bg-crit",
    symbol: "◆",
    to: "/indicators?classification=critical",
  },
  {
    key: "low",
    label: "Low",
    value: 3,
    stroke: "stroke-low",
    swatch: "bg-low",
    symbol: "●",
    to: "/indicators?classification=low",
  },
  { key: "not_assessed", label: "Not assessed", value: 0, stroke: "stroke-ink-400", swatch: "bg-ink-400", symbol: "–" },
];

function renderDonut(slices: DonutSlice[] = SLICES) {
  return render(
    <MemoryRouter>
      <Donut slices={slices} noun="indicator" label="Risk posture" centerCaption="indicators" emptyText="Nothing to show." />
    </MemoryRouter>,
  );
}

describe("Donut", () => {
  it("shows the total in the middle and a legend with counts and shares", () => {
    const { container } = renderDonut();

    const svg = svgOf(container);
    expect(within(svg).getByText("4")).toBeInTheDocument();
    expect(within(svg).getByText("indicators")).toBeInTheDocument();
    const legend = screen.getByRole("list", { name: "Risk posture" });
    expect(within(legend).getByRole("link", { name: "Critical: 1 indicator, 25%" })).toBeInTheDocument();
    expect(within(legend).getByRole("link", { name: "Low: 3 indicators, 75%" })).toBeInTheDocument();
  });

  it("links each slice to the indicators it counts, and leaves a slice without a place to go unlinked", () => {
    renderDonut();

    expect(screen.getByRole("link", { name: /^Critical/ })).toHaveAttribute(
      "href",
      "/indicators?classification=critical",
    );
    expect(screen.getAllByRole("link")).toHaveLength(2);
    expect(screen.getByRole("group", { name: "Not assessed: 0 indicators, 0%" })).toBeInTheDocument();
  });

  it("shows a slice in the middle while its legend entry is hovered or focused", async () => {
    const user = userEvent.setup();
    const { container } = renderDonut();
    const svg = svgOf(container);

    await user.hover(screen.getByRole("link", { name: /^Low/ }));
    expect(within(svg).getByText("3")).toBeInTheDocument();
    expect(within(svg).getByText("Low")).toBeInTheDocument();

    await user.unhover(screen.getByRole("link", { name: /^Low/ }));
    expect(within(svg).getByText("indicators")).toBeInTheDocument();

    await user.tab();
    expect(screen.getByRole("link", { name: /^Critical/ })).toHaveFocus();
    expect(within(svg).getByText("Critical")).toBeInTheDocument();
  });

  it("rounds a tiny share up to a visible '<1%' instead of 0%", () => {
    renderDonut([
      { ...(SLICES[0] as DonutSlice), value: 1 },
      { ...(SLICES[1] as DonutSlice), value: 400 },
    ]);

    expect(screen.getByRole("link", { name: "Critical: 1 indicator, <1%" })).toBeInTheDocument();
  });

  it("shows the empty text when there is nothing to split", () => {
    renderDonut(SLICES.map((slice) => ({ ...slice, value: 0 })));

    expect(screen.getByText("Nothing to show.")).toBeInTheDocument();
    expect(screen.queryByRole("list")).not.toBeInTheDocument();
  });
});
