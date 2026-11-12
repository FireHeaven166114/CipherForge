import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import HBarList, { type HBarItem } from "./HBarList";

const ITEMS: HBarItem[] = [
  { key: "NL", label: "Netherlands (NL)", count: 4, maxRisk: 80 },
  { key: "US", label: "United States (US)", count: 1, maxRisk: 12 },
  { key: "XX", label: "Unrated", count: 2, maxRisk: null },
];

describe("HBarList", () => {
  it("lists each row with its count and the highest risk behind it, in words", () => {
    render(<HBarList items={ITEMS} label="Top countries" noun="indicator" emptyText="None" />);

    const list = screen.getByRole("list", { name: "Top countries" });
    const rows = within(list).getAllByRole("listitem");
    expect(rows).toHaveLength(3);
    expect(rows[0]).toHaveTextContent("Netherlands (NL): 4 indicators, highest risk High");
    expect(rows[1]).toHaveTextContent("United States (US): 1 indicator, highest risk Informational");
    expect(rows[2]).toHaveTextContent("Unrated: 2 indicators");
    expect(rows[2]).not.toHaveTextContent("highest risk");
  });

  it("makes each row a button that reports which row was chosen", async () => {
    const user = userEvent.setup();
    const onSelect = vi.fn();
    render(<HBarList items={ITEMS} label="Top countries" noun="indicator" emptyText="None" onSelect={onSelect} />);

    await user.click(screen.getByRole("button", { name: /Netherlands/ }));

    expect(onSelect).toHaveBeenCalledWith("NL");
    expect(screen.getAllByRole("button")).toHaveLength(3);
  });

  it("has no buttons when nothing happens on a click", () => {
    render(<HBarList items={ITEMS} label="Top countries" noun="indicator" emptyText="None" />);

    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });

  it("shows at most the requested number of rows", () => {
    render(<HBarList items={ITEMS} label="Top countries" noun="indicator" emptyText="None" limit={2} />);

    expect(screen.getAllByRole("listitem")).toHaveLength(2);
    expect(screen.queryByText(/Unrated/)).not.toBeInTheDocument();
  });

  it("shows the empty text instead of an empty list", () => {
    render(<HBarList items={[]} label="Top countries" noun="indicator" emptyText="No countries yet." />);

    expect(screen.getByText("No countries yet.")).toBeInTheDocument();
    expect(screen.queryByRole("list")).not.toBeInTheDocument();
  });
});
