import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";

import Radar, { type RadarAxis } from "./Radar";

const AXES: RadarAxis[] = [
  { key: "ipv4", label: "IPv4", value: 6, to: "/indicators?type=ipv4" },
  { key: "ipv6", label: "IPv6", value: 1, to: "/indicators?type=ipv6" },
  { key: "domain", label: "Domain", value: 3 },
];

function renderRadar(axes: RadarAxis[] = AXES) {
  return render(
    <MemoryRouter>
      <Radar axes={axes} noun="indicator" label="Indicator mix" />
    </MemoryRouter>,
  );
}

describe("Radar", () => {
  it("names every axis with its count, and links the ones that lead somewhere", () => {
    renderRadar();

    expect(screen.getByRole("group", { name: "Indicator mix" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "IPv4: 6 indicators" })).toHaveAttribute(
      "href",
      "/indicators?type=ipv4",
    );
    expect(screen.getByRole("link", { name: "IPv6: 1 indicator" })).toBeInTheDocument();
    expect(screen.getByRole("img", { name: "Domain: 3 indicators" })).toBeInTheDocument();
  });

  it("draws nothing when there are too few axes to make a shape", () => {
    const { container } = renderRadar(AXES.slice(0, 2));

    expect(container.querySelector("svg")).toBeNull();
  });

  it("copes with all-zero data", () => {
    renderRadar(AXES.map((axis) => ({ ...axis, value: 0 })));

    expect(screen.getByRole("link", { name: "IPv4: 0 indicators" })).toBeInTheDocument();
  });
});
