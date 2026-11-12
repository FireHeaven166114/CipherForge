import { fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { longDay, shortDay } from "../../features/overview/dates";
import { svgOf } from "../../test/svg";
import AreaChart, { type AreaSeries } from "./AreaChart";

const CATEGORIES = ["2026-05-12", "2026-05-13", "2026-05-14"];
const SERIES: AreaSeries[] = [
  {
    id: "lookups",
    label: "Lookups",
    values: [2, 5, 9],
    line: "stroke-cipher",
    area: "fill-cipher/15",
    dot: "fill-cipher",
    swatch: "bg-cipher",
  },
  {
    id: "high",
    label: "High-risk lookups",
    values: [0, 1, 3],
    line: "stroke-crit",
    area: "fill-crit/15",
    dot: "fill-crit",
    swatch: "bg-crit",
  },
];

function renderChart(overrides: Partial<Parameters<typeof AreaChart>[0]> = {}) {
  return render(
    <AreaChart
      categories={CATEGORIES}
      axisLabel={shortDay}
      titleOf={longDay}
      series={SERIES}
      label="Lookups per day"
      {...overrides}
    />,
  );
}

describe("AreaChart", () => {
  it("gives assistive technology every number as a table", () => {
    renderChart();

    const table = screen.getByRole("table", { name: "Lookups per day" });
    const rows = within(table).getAllByRole("row");
    expect(rows).toHaveLength(4);
    expect(within(rows[0] as HTMLElement).getAllByRole("columnheader").map((cell) => cell.textContent)).toEqual([
      "Day",
      "Lookups",
      "High-risk lookups",
    ]);
    const last = rows[3] as HTMLElement;
    expect(within(last).getByRole("rowheader")).toHaveTextContent("Thu 14 May 2026");
    expect(within(last).getAllByRole("cell").map((cell) => cell.textContent)).toEqual(["9", "3"]);
  });

  it("labels the axes and lists the series", () => {
    const { container } = renderChart();

    const svg = svgOf(container);
    expect(within(svg).getByText("14 May")).toBeInTheDocument();
    expect(within(svg).getByText("12 May")).toBeInTheDocument();
    expect(screen.getByText("High-risk lookups", { selector: "li" })).toBeInTheDocument();
  });

  it("is inspected with the keyboard: focus shows the latest point, arrows move, Escape clears", async () => {
    const user = userEvent.setup();
    const { container } = renderChart();
    const status = screen.getByRole("status");
    expect(status).toHaveTextContent("");

    await user.tab();
    expect(screen.getByRole("group", { name: "Lookups per day" })).toHaveFocus();
    expect(status).toHaveTextContent("Thu 14 May 2026: Lookups 9, High-risk lookups 3");
    const svg = svgOf(container);
    expect(within(svg).getByText("Thu 14 May 2026")).toBeInTheDocument();

    await user.keyboard("{ArrowLeft}");
    expect(status).toHaveTextContent("Wed 13 May 2026: Lookups 5, High-risk lookups 1");

    await user.keyboard("{Home}");
    expect(status).toHaveTextContent("Tue 12 May 2026: Lookups 2, High-risk lookups 0");
    await user.keyboard("{ArrowLeft}");
    expect(status).toHaveTextContent("Tue 12 May 2026");

    await user.keyboard("{End}");
    expect(status).toHaveTextContent("Thu 14 May 2026");
    await user.keyboard("{ArrowRight}");
    expect(status).toHaveTextContent("Thu 14 May 2026");

    await user.keyboard("{Escape}");
    expect(status).toHaveTextContent("");
    expect(within(svg).queryByText("Thu 14 May 2026")).not.toBeInTheDocument();
  });

  it("hides the tooltip when focus leaves the chart", async () => {
    const user = userEvent.setup();
    renderChart();

    await user.tab();
    expect(screen.getByRole("status")).not.toBeEmptyDOMElement();
    await user.tab();

    expect(screen.getByRole("status")).toBeEmptyDOMElement();
  });

  it("follows the pointer to the nearest point", () => {
    const { container } = renderChart();
    const svg = svgOf(container);
    svg.getBoundingClientRect = () => ({ left: 0, top: 0, width: 640, height: 230 }) as DOMRect;

    fireEvent.pointerMove(svg, { clientX: 622 });
    expect(screen.getByRole("status")).toHaveTextContent("Thu 14 May 2026");

    fireEvent.pointerMove(svg, { clientX: 36 });
    expect(screen.getByRole("status")).toHaveTextContent("Tue 12 May 2026");

    fireEvent.pointerLeave(svg);
    expect(screen.getByRole("status")).toBeEmptyDOMElement();
  });

  it("says so when nothing was recorded", () => {
    const { container } = renderChart({
      series: SERIES.map((item) => ({ ...item, values: [0, 0, 0] })),
      emptyText: "No lookups in this period.",
    });

    const svg = svgOf(container);
    expect(within(svg).getByText("No lookups in this period.")).toBeInTheDocument();
  });

  it("shows only the message when there are no days at all", () => {
    renderChart({ categories: [], series: [], emptyText: "Nothing yet." });

    expect(screen.getByText("Nothing yet.")).toBeInTheDocument();
    expect(screen.queryByRole("group")).not.toBeInTheDocument();
  });
});
