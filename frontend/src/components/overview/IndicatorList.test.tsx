import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";

import { INDICATOR_ID, makeIndicator, makeNotAssessed } from "../../test/fixtures";
import IndicatorList from "./IndicatorList";

describe("IndicatorList", () => {
  it("opens the stored record from each row and shows the band with the score", () => {
    render(
      <MemoryRouter>
        <IndicatorList indicators={[makeIndicator()]} label="Highest risk" emptyText="Nothing." />
      </MemoryRouter>,
    );

    const list = screen.getByRole("list", { name: "Highest risk" });
    const row = within(list).getByRole("link", { name: /203\.0\.113\.9/ });
    expect(row).toHaveAttribute("href", `/indicators/${INDICATOR_ID}`);
    expect(row).toHaveTextContent("High");
    expect(row).toHaveTextContent("Score 80");
  });

  it("never turns a missing assessment into a clean-looking score", () => {
    render(
      <MemoryRouter>
        <IndicatorList indicators={[makeNotAssessed().indicator]} label="Latest" emptyText="Nothing." />
      </MemoryRouter>,
    );

    const row = screen.getByRole("link", { name: /203\.0\.113\.50/ });
    expect(row).toHaveTextContent("Not assessed");
    expect(row).toHaveTextContent("No score");
    expect(row).not.toHaveTextContent("Informational");
    expect(row).not.toHaveTextContent("Score 0");
  });

  it("explains an empty list instead of drawing nothing", () => {
    render(
      <MemoryRouter>
        <IndicatorList indicators={[]} label="Latest" emptyText="No indicators yet." />
      </MemoryRouter>,
    );
    expect(screen.getByText("No indicators yet.")).toBeInTheDocument();
    expect(screen.queryByRole("list")).not.toBeInTheDocument();
  });
});
