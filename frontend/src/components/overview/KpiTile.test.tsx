import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";

import KpiTile from "./KpiTile";

function renderTile(props: Partial<Parameters<typeof KpiTile>[0]> = {}) {
  render(
    <MemoryRouter>
      <ul>
        <KpiTile code="KPI-09" label="Things" value={5} to="/indicators" {...props} />
      </ul>
    </MemoryRouter>,
  );
  return screen.getByRole("link", { name: /^Things/ });
}

describe("KpiTile", () => {
  it("is one link that leads to the list behind the number", () => {
    const tile = renderTile({ to: "/indicators?sort=risk", note: "Counted today" });
    expect(tile).toHaveAttribute("href", "/indicators?sort=risk");
    expect(tile).toHaveTextContent("5");
    expect(tile).toHaveTextContent("Counted today");
  });

  it("states the change in words and keeps the decorative tag out of the accessible name", () => {
    const tile = renderTile({ trend: { direction: "up", text: "+2 vs 3 in the previous 24 hours" } });
    expect(tile).toHaveTextContent("+2 vs 3 in the previous 24 hours");
    expect(tile).not.toHaveAccessibleName(/KPI-09/);
  });

  it("draws no arrow when nothing changed", () => {
    const tile = renderTile({
      trend: { direction: "flat", text: "No change from 5 in the previous 24 hours" },
    });
    expect(tile.querySelector("svg")).toBeNull();
  });

  it("shortens a number that would not fit and keeps the exact figure for everyone else", () => {
    const tile = renderTile({ value: 987_654_321_012 });
    expect(tile).toHaveTextContent("987.7B");
    expect(tile).toHaveAccessibleName(/987,654,321,012/);
    expect(screen.getByTitle("987,654,321,012")).toBeInTheDocument();
  });

  it("prints an ordinary number in full, with nothing extra", () => {
    const tile = renderTile({ value: 12_480 });
    expect(tile).toHaveTextContent("12,480");
    expect(tile.querySelector("[title]")).toBeNull();
  });
});
