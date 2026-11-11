import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import {
  PULSE_ID,
  makeAbuseIpdb,
  makeInvestigation,
  makeNotAssessed,
  makeOtx,
} from "../../test/fixtures";
import InvestigationView from "./InvestigationView";

function cardFor(heading: string): HTMLElement {
  const section = screen.getByRole("heading", { name: heading }).closest("section");
  if (!section) throw new Error(`No card found for "${heading}"`);
  return section;
}

describe("InvestigationView", () => {
  it("shows the verdict, each provider on its own, the score breakdown and internal evidence", () => {
    render(<InvestigationView investigation={makeInvestigation()} />);

    const verdict = cardFor("CipherForge assessment");
    expect(within(verdict).getByText("203.0.113.9")).toBeInTheDocument();
    expect(within(verdict).getByText("High")).toBeInTheDocument();
    expect(within(verdict).getByText("80")).toBeInTheDocument();
    expect(within(verdict).getByText("90")).toBeInTheDocument();

    const abuse = cardFor("AbuseIPDB");
    expect(within(abuse).getByText("Queried live for this lookup")).toBeInTheDocument();
    expect(within(abuse).getByText(/AbuseIPDB's own measure/)).toBeInTheDocument();
    const otx = cardFor("AlienVault OTX");
    expect(within(otx).getByText("Stored answer from an earlier lookup")).toBeInTheDocument();
    expect(within(otx).getByText("Examplebot")).toBeInTheDocument();

    const table = screen.getByRole("table", { name: "Points that make up the score" });
    expect(within(table).getByRole("row", { name: /AbuseIPDB evidence/ })).toHaveTextContent("+45");
    expect(within(table).getByRole("row", { name: /Score \(out of 100\)/ })).toHaveTextContent("80");
    expect(screen.getByText(/never blocks, isolates or changes anything/)).toBeInTheDocument();
    expect(screen.getByText("How scores are calculated (intel-risk-v1)")).toBeInTheDocument();

    const internal = cardFor("Internal evidence");
    expect(within(internal).getByText("Not available")).toBeInTheDocument();
    expect(within(internal).getByText(/no internal telemetry/)).toBeInTheDocument();
  });

  it("says nothing was assessed, rather than showing a clean Informational result", () => {
    render(<InvestigationView investigation={makeNotAssessed()} />);

    const verdict = cardFor("CipherForge assessment");
    expect(within(verdict).getByText("Not assessed")).toBeInTheDocument();
    expect(within(verdict).queryByText("Informational")).not.toBeInTheDocument();
    expect(within(verdict).queryByText("Score")).not.toBeInTheDocument();
    expect(within(verdict).getByText(/This is not a clean result/)).toBeInTheDocument();

    expect(within(cardFor("AbuseIPDB")).getByText("Not configured")).toBeInTheDocument();
    expect(
      within(cardFor("AbuseIPDB")).getByText("AbuseIPDB is not configured (no API key set)."),
    ).toBeInTheDocument();
    expect(screen.getByText(/there is no score to break down/)).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });

  it("links only to well-formed OTX pulses and ATT&CK techniques, and opens them safely", () => {
    render(<InvestigationView investigation={makeInvestigation()} />);

    const pulse = screen.getByRole("link", { name: /Example phishing campaign/ });
    expect(pulse).toHaveAttribute("href", `https://otx.alienvault.com/pulse/${PULSE_ID}`);
    expect(pulse).toHaveAttribute("target", "_blank");
    expect(pulse).toHaveAttribute("rel", "noopener noreferrer");
    const technique = screen.getByRole("link", { name: /T1059\.001/ });
    expect(technique).toHaveAttribute("href", "https://attack.mitre.org/techniques/T1059/001/");
    expect(technique).toHaveAttribute("rel", "noopener noreferrer");
  });

  it("shows text from providers as inert text, never as markup or links", () => {
    const hostile = '<img src=x onerror="alert(1)"><script>alert(1)</script>';
    const abuse = makeAbuseIpdb();
    const otx = makeOtx();
    const { container } = render(
      <InvestigationView
        investigation={makeInvestigation({
          providers: [
            makeAbuseIpdb({
              message: hostile,
              tags: [hostile],
              summary: { ...abuse.summary, isp: hostile, notes: [hostile] },
            }),
            makeOtx({
              summary: {
                ...otx.summary,
                top_pulses: [{ id: "javascript:alert(1)", name: hostile, created: null, modified: null }],
                attack_ids: ["javascript:alert(1)"],
              },
            }),
          ],
        })}
      />,
    );

    expect(screen.getAllByText(hostile).length).toBeGreaterThanOrEqual(4);
    expect(container.querySelector("script, img, [onerror]")).toBeNull();
    expect(container.querySelector('a[href^="javascript:"]')).toBeNull();
  });
});
