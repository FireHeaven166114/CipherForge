import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";

import { INDICATOR_ID, makeIndicator, makeNotAssessed } from "../../test/fixtures";
import IndicatorTable from "./IndicatorTable";

const OTHER_ID = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d";

function renderTable() {
  const unassessed = makeNotAssessed().indicator;
  render(
    <MemoryRouter>
      <IndicatorTable
        caption="Test indicators"
        indicators={[makeIndicator(), { ...unassessed, indicator_id: OTHER_ID }]}
      />
    </MemoryRouter>,
  );
}

describe("IndicatorTable", () => {
  it("lists each indicator with its classification, score and confidence", () => {
    renderTable();

    expect(screen.getByRole("table", { name: "Test indicators" })).toBeInTheDocument();
    const row = screen.getByRole("row", { name: /203\.0\.113\.9 / });
    expect(within(row).getByText("High")).toBeInTheDocument();
    expect(within(row).getByText("80")).toBeInTheDocument();
    expect(within(row).getByText("90")).toBeInTheDocument();
    expect(within(row).getByRole("link", { name: "203.0.113.9" })).toHaveAttribute(
      "href",
      `/indicators/${INDICATOR_ID}`,
    );
  });

  it("marks an indicator no provider assessed as Not assessed, with no score to read as clean", () => {
    renderTable();

    const row = screen.getByRole("row", { name: /203\.0\.113\.50/ });
    expect(within(row).getByText("Not assessed")).toBeInTheDocument();
    expect(within(row).queryByText("Informational")).not.toBeInTheDocument();
    // Cells: type, classification, score, confidence, sources, status, last checked.
    const cells = within(row).getAllByRole("cell");
    expect(cells[2]).toHaveTextContent("—");
    expect(cells[3]).toHaveTextContent("—");
    expect(cells[2]).not.toHaveTextContent("0");
    expect(cells[3]).not.toHaveTextContent("0");
    expect(within(row).getByRole("link", { name: "203.0.113.50" })).toHaveAttribute(
      "href",
      `/indicators/${OTHER_ID}`,
    );
  });
});
