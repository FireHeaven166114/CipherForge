import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { ApiError } from "../../services/apiClient";
import { makeRules } from "../../test/networkFixtures";
import type { DetectionRule } from "../../types/network";
import RulesPanel from "./RulesPanel";

function withoutEnrichmentRule(): DetectionRule[] {
  return makeRules().map((rule) => (rule.rule_id === "NET-005" ? { ...rule, active: false } : rule));
}

function card(title: string): HTMLElement {
  const item = screen.getByRole("heading", { name: title }).closest("li");
  if (item === null) throw new Error(`No card for ${title}`);
  return item;
}

describe("RulesPanel", () => {
  it("lists every rule with its threshold, window and what each step of the ladder means", () => {
    render(<RulesPanel state={{ status: "success", data: makeRules() }} onRetry={vi.fn()} enrichmentEnabled />);

    const list = screen.getByRole("list", { name: "Detection rules" });
    expect(within(list).getAllByRole("heading", { level: 3 })).toHaveLength(7);
    for (const id of ["NET-001", "NET-002", "NET-003", "NET-004", "NET-005", "NET-006", "NET-007"]) {
      expect(within(list).getByText(id)).toBeInTheDocument();
    }

    const portScan = within(card("Port scan"));
    expect(portScan.getByText("20 ports")).toBeInTheDocument();
    expect(portScan.getByText("60 seconds")).toBeInTheDocument();
    expect(portScan.getByText("Description of port_scan.")).toBeInTheDocument();
    const ladder = portScan.getByRole("list", { name: "Severity of NET-001 by multiple of the threshold" });
    expect(within(ladder).getAllByRole("listitem").map((item) => item.textContent)).toEqual([
      expect.stringMatching(/At 1×.*Medium/),
      expect.stringMatching(/At 3×.*High/),
      expect.stringMatching(/At 10×.*Critical/),
    ]);
    expect(portScan.getByText("Active")).toBeInTheDocument();
  });

  it("gives the severity ladder the whole width of the card on a narrow screen", () => {
    render(<RulesPanel state={{ status: "success", data: makeRules() }} onRetry={vi.fn()} enrichmentEnabled />);

    const ladder = within(card("Port scan")).getByRole("list", {
      name: "Severity of NET-001 by multiple of the threshold",
    });
    expect(ladder.closest("dl")).toHaveClass(
      "grid-cols-1",
      "sm:grid-cols-[minmax(7rem,max-content)_minmax(0,1fr)]",
    );
  });

  it("shows a rule's detail, and says that a rule not about a span of time has no window", () => {
    render(<RulesPanel state={{ status: "success", data: makeRules() }} onRetry={vi.fn()} enrichmentEnabled />);

    expect(within(card("Repeated connections to suspicious ports")).getByText(/Ports: 23, 135/)).toBeInTheDocument();
    expect(within(card("Unexpected protocol")).getByText("No time window")).toBeInTheDocument();
  });

  it("explains why a rule that needs external enrichment is inactive", () => {
    render(
      <RulesPanel
        state={{ status: "success", data: withoutEnrichmentRule() }}
        onRetry={vi.fn()}
        enrichmentEnabled={false}
      />,
    );

    const inactive = within(card("Communication with a known malicious address"));
    expect(inactive.getAllByText("Inactive").length).toBeGreaterThan(0);
    expect(inactive.getByText(/needs external enrichment, which is switched off on this server/)).toBeInTheDocument();
    expect(inactive.getByText(/Needs external enrichment: only addresses that were looked up/)).toBeInTheDocument();
    expect(within(card("Port scan")).queryByText("Inactive")).not.toBeInTheDocument();
  });

  it("does not blame enrichment for an inactive rule when enrichment is on", () => {
    render(
      <RulesPanel
        state={{ status: "success", data: withoutEnrichmentRule() }}
        onRetry={vi.fn()}
        enrichmentEnabled
      />,
    );

    const inactive = within(card("Communication with a known malicious address"));
    expect(inactive.getByText("This rule cannot fire in the current configuration.")).toBeInTheDocument();
  });

  it("says that an alert is a lead, and that no alert does not mean safe", () => {
    render(<RulesPanel state={{ status: "success", data: makeRules() }} onRetry={vi.fn()} enrichmentEnabled />);
    expect(screen.getByText(/no alert is not proof that traffic is safe/)).toBeInTheDocument();
  });

  it("shows a loading note while the rules load", () => {
    render(<RulesPanel state={{ status: "loading" }} onRetry={vi.fn()} enrichmentEnabled />);
    expect(screen.getByRole("status")).toHaveTextContent("Loading detection rules");
  });

  it("shows why the rules could not be loaded and lets the analyst try again", async () => {
    const onRetry = vi.fn();
    const error = new ApiError({ message: "The API said no.", status: 403, code: "forbidden" });
    render(<RulesPanel state={{ status: "error", error }} onRetry={onRetry} enrichmentEnabled />);

    expect(screen.getByRole("alert")).toHaveTextContent("Security analyst role needed");
    await userEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(onRetry).toHaveBeenCalledTimes(1);
  });

  it("says so when the server lists no rules", () => {
    render(<RulesPanel state={{ status: "success", data: [] }} onRetry={vi.fn()} enrichmentEnabled />);
    expect(screen.getByText("The server reported no detection rules.")).toBeInTheDocument();
  });
});
