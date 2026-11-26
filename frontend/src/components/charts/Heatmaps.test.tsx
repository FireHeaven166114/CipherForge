import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";

import { makeOverview } from "../../test/fixtures";
import ActivityHeatmap from "./ActivityHeatmap";
import MatrixHeatmap from "./MatrixHeatmap";

describe("MatrixHeatmap", () => {
  function renderMatrix() {
    return render(
      <MemoryRouter>
        <MatrixHeatmap rows={makeOverview().matrix} />
      </MemoryRouter>,
    );
  }

  it("links every non-zero cell to the indicators of that type and risk band", () => {
    renderMatrix();

    const link = screen.getByRole("link", { name: "IPv4, Critical: 1 indicator" });
    expect(link).toHaveAttribute("href", "/indicators?type=ipv4&classification=critical");
    expect(screen.getByRole("link", { name: "IPv4, Informational: 2 indicators" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Domain, Medium: 1 indicator" })).toHaveAttribute(
      "href",
      "/indicators?type=domain&classification=medium",
    );
  });

  it("does not link empty cells", () => {
    renderMatrix();

    expect(screen.queryByRole("link", { name: /IPv4, Medium/ })).not.toBeInTheDocument();
    const domainRow = screen.getByRole("row", { name: /^Domain/ });
    expect(within(domainRow).getAllByRole("cell").map((cell) => cell.textContent)).toEqual([
      "0",
      "1",
      "1",
      "0",
      "0",
      "1",
      "3",
    ]);
  });

  it("links the 'not assessed' column to the indicators no provider answered for", () => {
    renderMatrix();

    expect(screen.getByRole("link", { name: "Domain, Not assessed: 1 indicator" })).toHaveAttribute(
      "href",
      "/indicators?type=domain&classification=not_assessed",
    );
  });

  it("links the type to all of its indicators and totals each row", () => {
    renderMatrix();

    expect(screen.getByRole("link", { name: "IPv4" })).toHaveAttribute("href", "/indicators?type=ipv4");
    const ipv4Row = screen.getByRole("row", { name: /^IPv4/ });
    expect(within(ipv4Row).getAllByRole("cell").at(-1)).toHaveTextContent("6");
  });

  it("describes the columns in words, calm to hot", () => {
    renderMatrix();

    const headers = screen.getAllByRole("columnheader").map((cell) => cell.textContent?.replace(/^[^A-Za-z]+/, ""));
    expect(headers).toEqual(["Type", "Informational", "Low", "Medium", "High", "Critical", "Not assessed", "Total"]);
  });
});

describe("ActivityHeatmap", () => {
  it("summarises each day for assistive technology: total lookups and the busiest hour", () => {
    render(<ActivityHeatmap rows={makeOverview().activity} />);

    const table = screen.getByRole("table", { name: /Lookups per day/ });
    const last = within(table).getByRole("row", { name: /Thu 14 May 2026/ });
    // The fixture puts 8 lookups in hour 09 and 1 in hour 14 on the last day.
    expect(within(last).getAllByRole("cell").map((cell) => cell.textContent)).toEqual(["9", "09:00 IST (8)"]);
    expect(within(table).getAllByRole("row")).toHaveLength(8);
  });

  it("titles every cell with the day, the IST hour and the count", () => {
    const { container } = render(<ActivityHeatmap rows={makeOverview().activity} />);

    const titles = Array.from(container.querySelectorAll("rect > title")).map((title) => title.textContent);
    expect(titles).toHaveLength(7 * 24);
    expect(titles).toContain("Thu 14 May 2026, 09:00 IST: 8 lookups");
    expect(titles).toContain("Thu 14 May 2026, 14:00 IST: 1 lookup");
    expect(titles).toContain("Thu 14 May 2026, 03:00 IST: 0 lookups");
  });

  it("says 'None' for a day without lookups", () => {
    render(<ActivityHeatmap rows={[{ day: "2026-05-14", hours: Array.from({ length: 24 }, () => 0) }]} />);

    expect(screen.getByRole("row", { name: /Thu 14 May 2026/ })).toHaveTextContent("None");
  });
});
