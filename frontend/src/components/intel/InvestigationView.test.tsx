import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import {
  PULSE_ID,
  makeAbuseIpdb,
  makeFailedProvider,
  makeIndicator,
  makeInvestigation,
  makeNotAssessed,
  makeOtx,
  makeThreatFox,
  makeVirusTotal,
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

  it("draws the score as segments beside each factor without adding to what is read out", () => {
    render(<InvestigationView investigation={makeInvestigation()} />);

    const table = screen.getByRole("table", { name: "Points that make up the score" });
    // One picture per factor and one for the score itself; none is exposed to assistive technology.
    const pictures = table.querySelectorAll("svg");
    expect(pictures).toHaveLength(5);
    for (const picture of pictures) expect(picture).toHaveAttribute("aria-hidden", "true");
    expect(within(table).getAllByRole("row")).toHaveLength(6);
    expect(within(table).getAllByRole("rowheader")).toHaveLength(5);
  });

  it("shows a cap that trims the score as a factor of its own", () => {
    const base = makeInvestigation();
    const capped = makeInvestigation({
      score: {
        ...base.score,
        score: 60,
        classification: "medium",
        factors: [
          ...base.score.factors,
          {
            code: "single_source_cap",
            label: "Single-source cap",
            points: -20,
            detail: "Fewer than two sources support this indicator, so the score cannot exceed 60.",
          },
        ],
      },
    });
    render(<InvestigationView investigation={capped} />);

    const table = screen.getByRole("table", { name: "Points that make up the score" });
    expect(within(table).getByRole("row", { name: /Single-source cap/ })).toHaveTextContent("-20");
    expect(within(table).getByRole("row", { name: /Score \(out of 100\)/ })).toHaveTextContent("60");
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

  describe("VirusTotal", () => {
    it("shows the engine results, the verdict and the community reputation", () => {
      render(
        <InvestigationView investigation={makeInvestigation({ providers: [makeVirusTotal()] })} />,
      );

      const card = cardFor("VirusTotal");
      expect(within(card).getByText("Malicious")).toBeInTheDocument();
      expect(within(card).getByText("Answered")).toBeInTheDocument();
      expect(
        within(card).getByText("7 malicious, 1 suspicious, 55 harmless, 12 undetected (75 engines)"),
      ).toBeInTheDocument();
      expect(within(card).getByText(/^-14 \(VirusTotal community score/)).toBeInTheDocument();
      expect(within(card).getByText("trojan.examplebot")).toBeInTheDocument();
      expect(within(card).getByText("Example Hosting Ltd", { exact: false })).toBeInTheDocument();
      expect(within(card).getByText("Last analysed")).toBeInTheDocument();
      expect(within(card).getByText("First submitted")).toBeInTheDocument();
    });

    it("links to the VirusTotal report only when the link has VirusTotal's own shape", () => {
      const good = render(
        <InvestigationView investigation={makeInvestigation({ providers: [makeVirusTotal()] })} />,
      );
      const link = within(cardFor("VirusTotal")).getByRole("link", {
        name: /Open the VirusTotal report/,
      });
      expect(link).toHaveAttribute("href", "https://www.virustotal.com/gui/ip-address/203.0.113.9");
      expect(link).toHaveAttribute("target", "_blank");
      expect(link).toHaveAttribute("rel", "noopener noreferrer");
      good.unmount();

      const base = makeVirusTotal();
      render(
        <InvestigationView
          investigation={makeInvestigation({
            providers: [
              makeVirusTotal({
                summary: { ...base.summary, provider_link: "https://evil.test/gui/domain/x" },
              }),
            ],
          })}
        />,
      );
      expect(within(cardFor("VirusTotal")).queryByRole("link")).not.toBeInTheDocument();
    });

    it("says a harmless or not-found verdict is not proof of safety, and does not draw it as safe", () => {
      const base = makeVirusTotal();
      render(
        <InvestigationView
          investigation={makeInvestigation({
            providers: [
              makeVirusTotal({
                verdict: "harmless",
                signal: 0,
                summary: { ...base.summary, malicious: 0, suspicious: 0, verdict: "harmless" },
              }),
            ],
          })}
        />,
      );

      const card = cardFor("VirusTotal");
      expect(within(card).getByText("Harmless")).toBeInTheDocument();
      expect(within(card).getByText(/not proof that the indicator is safe/)).toBeInTheDocument();
      expect(within(card).queryByText("Safe")).not.toBeInTheDocument();
    });

    it("reads a record with no analysis as no data, with the provider's verdict", () => {
      render(
        <InvestigationView
          investigation={makeInvestigation({
            providers: [
              makeVirusTotal({
                status: "no_data",
                verdict: "not_found",
                signal: null,
                freshness: "fresh",
                evidence_at: null,
                first_evidence_at: null,
                summary: { verdict: "not_found", analysis_status: "not_found", notes: [] },
              }),
            ],
          })}
        />,
      );

      const card = cardFor("VirusTotal");
      expect(within(card).getByText("No data")).toBeInTheDocument();
      expect(within(card).getByText("Not found")).toBeInTheDocument();
      expect(within(card).getByText(/VirusTotal has no record of it/)).toBeInTheDocument();
    });
  });

  describe("ThreatFox", () => {
    it("shows each record with the reporter's confidence, and says what that number is not", () => {
      render(
        <InvestigationView investigation={makeInvestigation({ providers: [makeThreatFox()] })} />,
      );

      const card = cardFor("ThreatFox");
      expect(within(card).getByText("2 records matching this indicator")).toBeInTheDocument();
      expect(within(card).getByText(/It is not a detection count/)).toBeInTheDocument();
      expect(within(card).getByText("203.0.113.9:443")).toBeInTheDocument();
      expect(within(card).getByText("203.0.113.9:8080")).toBeInTheDocument();
      expect(within(card).getByText(/aka Samplebot/)).toBeInTheDocument();
      expect(within(card).getByText("Reported by example-reporter")).toBeInTheDocument();
      expect(within(card).getAllByText("(assigned by the reporter)")).toHaveLength(2);
    });

    it("shows the reporter's address defanged and as text, never as a link", () => {
      render(
        <InvestigationView investigation={makeInvestigation({ providers: [makeThreatFox()] })} />,
      );

      const card = cardFor("ThreatFox");
      expect(within(card).getByText("hxxps://reports.example.test/examplebot")).toBeInTheDocument();
      expect(within(card).queryByText("https://reports.example.test/examplebot")).not.toBeInTheDocument();
      for (const link of within(card).getAllByRole("link")) {
        expect(link.getAttribute("href")).not.toContain("reports.example.test");
      }
    });

    it("links only to ThreatFox and Malpedia, built from valid ids and addresses", () => {
      const base = makeThreatFox();
      const matches = (base.summary.matches as Record<string, unknown>[]).map((match, index) =>
        index === 0
          ? match
          : {
              ...match,
              id: "javascript:alert(1)",
              malpedia_url: "https://evil.test/details/win.examplebot",
            },
      );
      render(
        <InvestigationView
          investigation={makeInvestigation({
            providers: [makeThreatFox({ summary: { ...base.summary, matches } })],
          })}
        />,
      );

      const links = within(cardFor("ThreatFox")).getAllByRole("link");
      expect(links.map((link) => link.getAttribute("href"))).toEqual([
        "https://threatfox.abuse.ch/ioc/1234567/",
        "https://malpedia.caad.fkie.fraunhofer.de/details/win.examplebot",
      ]);
      for (const link of links) expect(link).toHaveAttribute("rel", "noopener noreferrer");
    });

    it("words the summary dates as the reporters' first and last sighting", () => {
      render(
        <InvestigationView investigation={makeInvestigation({ providers: [makeThreatFox()] })} />,
      );
      const card = cardFor("ThreatFox");
      expect(within(card).getByText("Last seen", { selector: "dt" })).toBeInTheDocument();
      expect(within(card).getByText("First seen", { selector: "dt" })).toBeInTheDocument();
      expect(within(card).queryByText("Latest activity")).not.toBeInTheDocument();
    });
  });

  describe("a provider that gave no answer", () => {
    const attempt = makeIndicator({ last_checked_at: "2026-05-02T09:30:00Z" });

    function failing(
      reason: Parameters<typeof makeFailedProvider>[3],
      status: Parameters<typeof makeFailedProvider>[2] = "error",
      message = "The provider did not answer.",
    ) {
      return makeInvestigation({
        indicator: attempt,
        providers: [makeFailedProvider("virustotal", "VirusTotal", status, reason, message)],
      });
    }

    it.each([
      ["auth_failed", "error", "Authentication failure"],
      ["timeout", "error", "Timeout"],
      ["unavailable", "error", "Provider unavailable"],
      ["malformed_response", "error", "Malformed response"],
      ["invalid_input", "error", "Invalid input"],
    ] as const)("names the reason %s beside the status", (reason, status, label) => {
      render(<InvestigationView investigation={failing(reason, status)} />);

      const card = cardFor("VirusTotal");
      expect(within(card).getByText("Error")).toBeInTheDocument();
      expect(within(card).getByText(label)).toBeInTheDocument();
      expect(within(card).getByText("The provider did not answer.")).toBeInTheDocument();
    });

    it("shows a rate limit once, because the status and the reason say the same thing", () => {
      render(<InvestigationView investigation={failing("rate_limited", "rate_limited")} />);
      expect(within(cardFor("VirusTotal")).getAllByText("Rate limited")).toHaveLength(1);
    });

    it("says when the lookup was attempted, in India Standard Time", () => {
      render(<InvestigationView investigation={failing("timeout")} />);
      expect(within(cardFor("VirusTotal")).getByText(/Lookup attempted/)).toBeInTheDocument();
      expect(within(cardFor("VirusTotal")).getByText(/02-05-2026 03:00:00 PM IST/)).toBeInTheDocument();
    });

    it("says nothing about an attempt for a provider that was never asked", () => {
      render(<InvestigationView investigation={failing("not_configured", "not_configured")} />);
      expect(within(cardFor("VirusTotal")).queryByText(/Lookup attempted/)).not.toBeInTheDocument();
    });

    it("falls back to its own explanation when the API sends no message", () => {
      const investigation = makeInvestigation({
        indicator: attempt,
        providers: [
          { ...makeFailedProvider("virustotal", "VirusTotal", "error", "timeout", ""), message: null },
        ],
      });
      render(<InvestigationView investigation={investigation} />);
      expect(within(cardFor("VirusTotal")).getByText("The provider did not answer in time.")).toBeInTheDocument();
    });

    it.each(["rate_limited", "timeout", "unavailable", "malformed_response"] as const)(
      "offers Retry for %s and asks again without forcing a refresh",
      async (reason) => {
        const onRetry = vi.fn();
        const user = userEvent.setup();
        render(<InvestigationView investigation={failing(reason)} onRetry={onRetry} />);

        await user.click(within(cardFor("VirusTotal")).getByRole("button", { name: "Retry VirusTotal" }));
        expect(onRetry).toHaveBeenCalledTimes(1);
      },
    );

    it.each(["not_configured", "auth_failed", "invalid_input"] as const)(
      "offers no Retry for %s, which asking again cannot fix",
      (reason) => {
        render(<InvestigationView investigation={failing(reason)} onRetry={vi.fn()} />);
        expect(within(cardFor("VirusTotal")).queryByRole("button")).not.toBeInTheDocument();
      },
    );

    it("offers no Retry where the page gave no way to ask again", () => {
      render(<InvestigationView investigation={failing("timeout")} />);
      expect(within(cardFor("VirusTotal")).queryByRole("button")).not.toBeInTheDocument();
    });

    it("does not send a second request while a retry is running", async () => {
      const onRetry = vi.fn();
      const user = userEvent.setup();
      render(<InvestigationView investigation={failing("timeout")} onRetry={onRetry} retrying />);

      const button = within(cardFor("VirusTotal")).getByRole("button", { name: /Retrying/ });
      expect(button).toHaveAttribute("aria-disabled", "true");
      await user.click(button);
      expect(onRetry).not.toHaveBeenCalled();
    });

    it("offers no Retry on a provider that answered", () => {
      render(
        <InvestigationView
          investigation={makeInvestigation({ providers: [makeVirusTotal(), makeThreatFox()] })}
          onRetry={vi.fn()}
        />,
      );
      expect(screen.queryByRole("button", { name: /^Retry / })).not.toBeInTheDocument();
    });
  });

  it("shows four providers side by side, each under its own name", () => {
    render(
      <InvestigationView
        investigation={makeInvestigation({
          providers: [makeAbuseIpdb(), makeOtx(), makeVirusTotal(), makeThreatFox()],
        })}
      />,
    );

    for (const name of ["AbuseIPDB", "AlienVault OTX", "VirusTotal", "ThreatFox"]) {
      expect(within(cardFor(name)).getByText("Answered")).toBeInTheDocument();
    }
  });

  it("shows text from VirusTotal and ThreatFox as inert text, never as markup or links", () => {
    const hostile = '<img src=x onerror="alert(1)"><script>alert(1)</script>';
    const vt = makeVirusTotal();
    const tf = makeThreatFox();
    const { container } = render(
      <InvestigationView
        investigation={makeInvestigation({
          providers: [
            makeVirusTotal({
              message: hostile,
              tags: [hostile],
              summary: {
                ...vt.summary,
                threat_label: hostile,
                threat_names: [hostile],
                categories: [hostile],
                file_name: hostile,
                as_owner: hostile,
                provider_link: `javascript:alert(1)`,
                notes: [hostile],
              },
            }),
            makeThreatFox({
              summary: {
                ...tf.summary,
                matches: [
                  {
                    id: "javascript:alert(1)",
                    ioc: hostile,
                    malware: hostile,
                    reporter: hostile,
                    reference: "javascript:alert(1)",
                    malpedia_url: "javascript:alert(1)",
                    tags: [hostile],
                  },
                ],
                threat_types: [hostile],
                malware_families: [hostile],
              },
            }),
          ],
        })}
      />,
    );

    expect(screen.getAllByText(hostile, { exact: false }).length).toBeGreaterThanOrEqual(8);
    expect(container.querySelector("script, img, [onerror]")).toBeNull();
    expect(container.querySelector('a[href^="javascript:"]')).toBeNull();
    expect(container.querySelector("a")).toBeNull();
  });
});
