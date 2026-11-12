import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { describe, expect, it, vi } from "vitest";

import { INDICATOR_ID, makeFacet, makeSample } from "../../test/fixtures";
import FocusDrawer, { type Focus } from "./FocusDrawer";

function renderDrawer(focus: Focus | null, onClose = vi.fn()) {
  render(
    <MemoryRouter>
      <FocusDrawer focus={focus} onClose={onClose} />
    </MemoryRouter>,
  );
  return onClose;
}

describe("FocusDrawer", () => {
  it("renders nothing while no value is selected", () => {
    renderDrawer(null);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("names the value, counts its indicators and shows the highest risk", () => {
    renderDrawer({ kind: "tag", entry: makeFacet("scanner", 3, 80) });

    const dialog = screen.getByRole("dialog", { name: "Provider tag: scanner" });
    expect(within(dialog).getByText("Indicators").nextSibling).toHaveTextContent("3");
    expect(within(dialog).getByText("Highest risk").nextSibling).toHaveTextContent("High");
    expect(within(dialog).getByText("Highest risk").nextSibling).toHaveTextContent("80");
    expect(within(dialog).queryByText(/not where an attacker is/)).not.toBeInTheDocument();
  });

  it("says how many of the indicators are listed when there are more than the samples", () => {
    renderDrawer({ kind: "malware", entry: makeFacet("Examplebot", 7, 80) });
    expect(screen.getByText("Showing 1 of 7 indicators.")).toBeInTheDocument();
  });

  it("does not claim a partial list when every indicator is shown", () => {
    renderDrawer({ kind: "malware", entry: makeFacet("Examplebot", 1, 80) });
    expect(screen.queryByText(/^Showing /)).not.toBeInTheDocument();
  });

  it("writes a country as a name and warns that it is not where an attacker is", () => {
    renderDrawer({ kind: "country", entry: makeFacet("NL", 4, 80) });

    const dialog = screen.getByRole("dialog", { name: "Provider-reported country: Netherlands (NL)" });
    expect(dialog).toHaveTextContent("not where an attacker is");
    expect(dialog).toHaveTextContent("says nothing about domains, URLs or file hashes");
  });

  it("offers the MITRE page only for a technique that is written as one", () => {
    renderDrawer({ kind: "technique", entry: makeFacet("T1566", 2, 80) });
    expect(screen.getByRole("link", { name: /Read about T1566/ })).toHaveAttribute(
      "href",
      "https://attack.mitre.org/techniques/T1566/",
    );
  });

  it("does not build a MITRE link from text a provider made up", () => {
    renderDrawer({ kind: "technique", entry: makeFacet("../../evil?x=1", 1, 10) });
    expect(screen.queryByRole("link", { name: /MITRE/ })).not.toBeInTheDocument();
  });

  it("closes when a listed indicator is opened, so the drawer does not follow the user", async () => {
    const user = userEvent.setup();
    const onClose = renderDrawer({
      kind: "tag",
      entry: makeFacet("scanner", 1, 80, [makeSample()]),
    });

    const link = screen.getByRole("link", { name: "203.0.113.9" });
    expect(link).toHaveAttribute("href", `/indicators/${INDICATOR_ID}`);
    await user.click(link);

    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("closes from the close button", async () => {
    const user = userEvent.setup();
    const onClose = renderDrawer({ kind: "tag", entry: makeFacet("scanner", 1, 80) });

    await user.click(screen.getByRole("button", { name: "Close details" }));

    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("says so when there is no indicator to list", () => {
    renderDrawer({ kind: "tag", entry: makeFacet("scanner", 0, 0, []) });
    expect(screen.getByText("No indicator is listed for this value.")).toBeInTheDocument();
  });
});
