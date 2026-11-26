import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { SCANNER_IP, makeCompletedEnrichment, makeEnrichment } from "../../test/networkFixtures";
import type { EnrichmentState } from "../../types/network";
import EnrichmentDetail from "./EnrichmentDetail";

const WITHOUT_ANSWER: [EnrichmentState, string, string][] = [
  ["not_looked_up", "Not looked up", "This address has not been looked up. Nothing was sent to any provider."],
  ["pending", "Looking up", "The lookup is waiting for the providers."],
  ["failed", "Lookup failed", "The lookup failed."],
  ["unavailable", "Lookup unavailable", "No provider could be asked for this address right now."],
  ["skipped_budget", "Lookup limit reached", "Not looked up: this session reached its limit on lookups."],
  ["disabled", "Enrichment off", "External enrichment is switched off on this server."],
  ["not_applicable", "No public address", "The traffic involves no public address, so there is nothing to look up."],
];

describe("EnrichmentDetail", () => {
  it.each(WITHOUT_ANSWER)("says what %s means, with no score and no verdict", (status, label, note) => {
    render(<EnrichmentDetail enrichment={makeEnrichment({ status })} />);

    expect(screen.getByText(label)).toBeInTheDocument();
    expect(screen.getByText(note)).toBeInTheDocument();
    expect(screen.queryByText(/Risk score/)).not.toBeInTheDocument();
    expect(screen.queryByText("Classification")).not.toBeInTheDocument();
    expect(screen.queryByText(/safe|clean/i)).not.toBeInTheDocument();
  });

  it("gives the reason a lookup failed or was unavailable when the server states one", () => {
    const { rerender } = render(
      <EnrichmentDetail enrichment={makeEnrichment({ status: "failed", message: "The provider timed out." })} />,
    );
    expect(screen.getByText("The provider timed out.")).toBeInTheDocument();

    rerender(
      <EnrichmentDetail
        enrichment={makeEnrichment({ status: "unavailable", message: "No provider is configured." })}
      />,
    );
    expect(screen.getByText("No provider is configured.")).toBeInTheDocument();
  });

  it("shows the score, its classification, the providers and when the lookup was made", () => {
    render(<EnrichmentDetail enrichment={makeCompletedEnrichment()} />);

    // The badge and the line that says when the lookup was made.
    expect(screen.getAllByText("Looked up")).toHaveLength(2);
    expect(screen.getByText(SCANNER_IP)).toBeInTheDocument();
    expect(screen.getByText("Risk score 72 of 100")).toBeInTheDocument();
    expect(screen.getByText("Classification")).toBeInTheDocument();
    expect(screen.getByText("High")).toBeInTheDocument();
    expect(screen.getByText(/a signal, not a verdict/)).toBeInTheDocument();
    const providers = screen.getByRole("list", { name: "Provider answers" });
    expect(within(providers).getAllByRole("listitem").map((item) => item.textContent)).toEqual([
      "AbuseIPDB: Answered, verdict malicious",
      "AlienVault OTX: No data",
    ]);
    expect(screen.getByText("20-05-2026 02:02:00 PM IST")).toBeInTheDocument();
  });

  it("never turns no data into a verdict: no score, no classification, and a plain warning", () => {
    render(
      <EnrichmentDetail
        enrichment={makeCompletedEnrichment({
          risk_score: null,
          classification: null,
          assessed: false,
          providers: [{ provider: "otx", display_name: "AlienVault OTX", status: "no_data", verdict: null }],
        })}
      />,
    );

    expect(screen.getAllByText("Looked up")).toHaveLength(2);
    expect(screen.getByText("No provider returned data. This is not evidence the address is safe.")).toBeInTheDocument();
    expect(screen.queryByText(/Risk score/)).not.toBeInTheDocument();
    expect(screen.queryByText("Classification")).not.toBeInTheDocument();
    expect(screen.getByText("AlienVault OTX: No data")).toBeInTheDocument();
  });

  it("shows no score the server flags as resting on no evidence, even if it sent one", () => {
    render(
      <EnrichmentDetail
        enrichment={makeCompletedEnrichment({ risk_score: 0, classification: "informational", assessed: false })}
      />,
    );

    expect(screen.queryByText(/Risk score/)).not.toBeInTheDocument();
    expect(screen.queryByText("Classification")).not.toBeInTheDocument();
    expect(screen.queryByText("Informational")).not.toBeInTheDocument();
    expect(screen.getByText("No provider returned data. This is not evidence the address is safe.")).toBeInTheDocument();
  });

  it("treats a score of zero as a score, because zero is not the same as no data", () => {
    render(<EnrichmentDetail enrichment={makeCompletedEnrichment({ risk_score: 0, classification: "informational" })} />);

    expect(screen.getByText("Risk score 0 of 100")).toBeInTheDocument();
    expect(screen.getByText("Informational")).toBeInTheDocument();
  });

  it("writes out a classification this console does not know, as plain text", () => {
    render(<EnrichmentDetail enrichment={makeCompletedEnrichment({ classification: "very_odd" })} />);

    expect(screen.getByText("Very odd")).toBeInTheDocument();
  });

  it("lets what a provider or the server says wrap inside its box, however long the word", () => {
    render(
      <EnrichmentDetail
        enrichment={makeCompletedEnrichment({
          classification: "very_odd",
          providers: [{ provider: "x", display_name: "Provider", status: "ok", verdict: "W".repeat(300) }],
        })}
      />,
    );

    expect(screen.getByText("Very odd")).toHaveClass("break-words", "max-w-full");
    expect(screen.getByRole("list", { name: "Provider answers" })).toHaveClass("break-words");
    expect(screen.getByText(/^Providers answered\./)).toHaveClass("break-words");
  });

  it("can leave the address out when the row around it already names it", () => {
    render(<EnrichmentDetail enrichment={makeCompletedEnrichment()} showAddress={false} />);

    expect(screen.queryByText(SCANNER_IP)).not.toBeInTheDocument();
  });

  it("shows a provider's own word as text, never as markup", () => {
    const hostile = '<img src=x onerror="alert(1)">';
    const { container } = render(
      <EnrichmentDetail
        enrichment={makeCompletedEnrichment({
          providers: [{ provider: "x", display_name: "Provider", status: "ok", verdict: hostile }],
        })}
      />,
    );

    expect(screen.getByText(`Provider: Answered, verdict ${hostile}`)).toBeInTheDocument();
    expect(container.querySelector("img")).toBeNull();
  });
});
