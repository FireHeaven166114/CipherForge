import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { apiError, networkApi, requested } from "../../test/networkApi";
import {
  ALERT_ID,
  HOST_IP,
  SCANNER_IP,
  makeAlert,
  makeCompletedEnrichment,
  makeEnrichment,
} from "../../test/networkFixtures";
import type { EnrichmentState, NetworkAlert } from "../../types/network";
import AlertRow from "./AlertRow";

function setup(
  alert: NetworkAlert = makeAlert(),
  options: { enrichmentEnabled?: boolean; handlers?: Parameters<typeof networkApi>[0] } = {},
) {
  const fetchMock = networkApi(options.handlers);
  const onEnriched = vi.fn();
  render(
    <ul>
      <AlertRow alert={alert} enrichmentEnabled={options.enrichmentEnabled ?? true} onEnriched={onEnriched} />
    </ul>,
  );
  return { fetchMock, onEnriched };
}

const lookupButton = () => screen.queryByRole("button", { name: /^Look up address/ });

describe("AlertRow: what fired", () => {
  it("shows the severity as a word, the rule, what it saw and against which threshold", () => {
    setup();

    expect(screen.getByText("High")).toBeInTheDocument();
    expect(screen.getByText("NET-001")).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 3, name: "Port scan" })).toBeInTheDocument();
    expect(screen.getByText(`${SCANNER_IP} tried 40 different destination ports within 60 seconds.`)).toBeInTheDocument();
    expect(screen.getByText("Observed 40 ports against a threshold of 20 ports, within 60 seconds.")).toBeInTheDocument();
  });

  it("names the traffic and gives both times in IST", () => {
    setup(makeAlert({ dst_port: 22 }));

    expect(screen.getByText("Source").nextElementSibling).toHaveTextContent(SCANNER_IP);
    expect(screen.getByText("Destination").nextElementSibling).toHaveTextContent(`${HOST_IP}:22`);
    expect(screen.getByText("Protocol").nextElementSibling).toHaveTextContent("TCP");
    expect(screen.getByText("First observed").nextElementSibling).toHaveTextContent("20-05-2026 02:00:05 PM IST");
    expect(screen.getByText("Last observed").nextElementSibling).toHaveTextContent("20-05-2026 02:00:45 PM IST");
  });

  it("leaves out the parts of the traffic the alert does not name", () => {
    setup(makeAlert({ src_ip: null, dst_ip: null, dst_port: null, protocol: null }));

    expect(screen.queryByText("Source")).not.toBeInTheDocument();
    expect(screen.queryByText("Destination")).not.toBeInTheDocument();
    expect(screen.queryByText("Protocol")).not.toBeInTheDocument();
  });

  it("shows every severity with its own word", () => {
    for (const [severity, word] of [
      ["low", "Low"],
      ["medium", "Medium"],
      ["high", "High"],
      ["critical", "Critical"],
    ] as const) {
      const { unmount } = render(
        <ul>
          <AlertRow alert={makeAlert({ severity })} enrichmentEnabled onEnriched={vi.fn()} />
        </ul>,
      );
      expect(screen.getByText(word)).toBeInTheDocument();
      unmount();
    }
  });

  it("shows what the server wrote as text, never as markup", () => {
    const hostile = '<script>alert("x")</script><img src=x onerror=alert(1)>';
    const { container } = render(
      <ul>
        <AlertRow
          alert={makeAlert({ title: hostile, explanation: hostile, evidence: { note: hostile } })}
          enrichmentEnabled
          onEnriched={vi.fn()}
        />
      </ul>,
    );

    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
    expect(screen.getAllByText(hostile).length).toBeGreaterThan(0);
  });
});

describe("AlertRow: evidence", () => {
  it("keeps the evidence closed until it is asked for, and closes it again", async () => {
    setup();

    const toggle = screen.getByRole("button", { name: "Evidence for rule NET-001" });
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByText("Distinct ports")).not.toBeInTheDocument();

    await userEvent.click(toggle);
    expect(toggle).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByText("Distinct ports").nextElementSibling).toHaveTextContent("40");
    expect(screen.getByText("Sample ports").nextElementSibling).toHaveTextContent("1, 2, 3");

    await userEvent.click(toggle);
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByText("Distinct ports")).not.toBeInTheDocument();
  });

  it("points its toggle at the region it opens", async () => {
    setup();

    const toggle = screen.getByRole("button", { name: "Evidence for rule NET-001" });
    await userEvent.click(toggle);

    const controlled = toggle.getAttribute("aria-controls");
    expect(controlled).not.toBeNull();
    expect(document.getElementById(controlled ?? "")).toContainElement(screen.getByText("Distinct ports"));
  });

  it("can be opened from the keyboard", async () => {
    setup();

    await userEvent.tab();
    const toggle = screen.getByRole("button", { name: "Evidence for rule NET-001" });
    expect(toggle).toHaveFocus();
    await userEvent.keyboard("{Enter}");

    expect(screen.getByText("Distinct ports")).toBeInTheDocument();
  });

  it("says so when an alert recorded nothing more", async () => {
    setup(makeAlert({ evidence: {} }));

    await userEvent.click(screen.getByRole("button", { name: "Evidence for rule NET-001" }));

    expect(screen.getByText("This alert recorded no further evidence.")).toBeInTheDocument();
  });
});

describe("AlertRow: address lookup", () => {
  const OFFER: EnrichmentState[] = ["not_looked_up", "failed", "unavailable", "skipped_budget"];
  const NO_OFFER: EnrichmentState[] = ["completed", "pending", "disabled", "not_applicable"];

  it.each(OFFER)("offers the lookup when the address is %s", (status) => {
    setup(makeAlert({ enrichment: makeEnrichment({ status, address: SCANNER_IP }) }));

    expect(lookupButton()).toBeInTheDocument();
    expect(screen.getByText("Only the public address is sent to the providers, never the traffic.")).toBeInTheDocument();
  });

  it.each(NO_OFFER)("does not offer the lookup when the address is %s", (status) => {
    setup(makeAlert({ enrichment: makeEnrichment({ status, address: SCANNER_IP }) }));

    expect(lookupButton()).not.toBeInTheDocument();
  });

  it("does not offer a lookup at all when the server has enrichment switched off", () => {
    setup(makeAlert(), { enrichmentEnabled: false });

    expect(lookupButton()).not.toBeInTheDocument();
  });

  it("looks the address up and shows the answer in the same row", async () => {
    const { fetchMock, onEnriched } = setup(makeAlert(), {
      handlers: { enrich: () => makeAlert({ enrichment: makeCompletedEnrichment() }) },
    });
    expect(screen.getByText("Not looked up")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Look up address for rule NET-001" }));

    expect(await screen.findByText("Risk score 72 of 100")).toBeInTheDocument();
    expect(screen.getAllByText("Looked up").length).toBeGreaterThan(0);
    expect(screen.queryByText("Not looked up")).not.toBeInTheDocument();
    expect(screen.getByText("AbuseIPDB: Answered, verdict malicious")).toBeInTheDocument();
    expect(lookupButton()).not.toBeInTheDocument();
    const post = fetchMock.mock.calls.find(([, init]) => init?.method === "POST");
    expect(post?.[0]).toBe(`/api/v1/network/alerts/${ALERT_ID}/enrich`);
    expect(onEnriched).toHaveBeenCalledTimes(1);
    expect(onEnriched.mock.calls[0]?.[0]).toMatchObject({ id: ALERT_ID });
  });

  it("shows an answer that holds no data without calling it safe", async () => {
    setup(makeAlert(), {
      handlers: {
        enrich: () =>
          makeAlert({
            enrichment: makeCompletedEnrichment({ risk_score: null, classification: null, assessed: false }),
          }),
      },
    });

    await userEvent.click(screen.getByRole("button", { name: "Look up address for rule NET-001" }));

    expect(await screen.findByText("No provider returned data. This is not evidence the address is safe.")).toBeInTheDocument();
    expect(screen.queryByText(/Risk score/)).not.toBeInTheDocument();
  });

  it("keeps the button for another try when the lookup failed", async () => {
    setup(makeAlert(), {
      handlers: {
        enrich: () =>
          makeAlert({ enrichment: makeEnrichment({ status: "failed", address: SCANNER_IP, message: "The provider timed out." }) }),
      },
    });

    await userEvent.click(screen.getByRole("button", { name: "Look up address for rule NET-001" }));

    expect(await screen.findByText("Lookup failed")).toBeInTheDocument();
    expect(screen.getByText("The provider timed out.")).toBeInTheDocument();
    expect(lookupButton()).toBeInTheDocument();
  });

  it("holds the button while the lookup runs, and sends it once", async () => {
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const { fetchMock } = setup(makeAlert(), {
      handlers: {
        enrich: async () => {
          await gate;
          return makeAlert({ enrichment: makeCompletedEnrichment() });
        },
      },
    });

    await userEvent.click(screen.getByRole("button", { name: "Look up address for rule NET-001" }));
    const busy = await screen.findByRole("button", { name: /Looking up…/ });
    expect(busy).toHaveAttribute("aria-disabled", "true");
    await userEvent.click(busy);
    release?.();

    await screen.findByText("Risk score 72 of 100");
    expect(requested(fetchMock, "POST")).toHaveLength(1);
  });

  it("announces the lookup politely", () => {
    setup();

    const region = screen.getByText("Address lookup").parentElement;
    expect(region).toHaveAttribute("aria-live", "polite");
  });

  it.each([
    [409, "enrichment_disabled", "External enrichment is switched off"],
    [422, "address_not_public", "Nothing to look up"],
    [404, "alert_not_found", "Alert not found"],
  ])("explains a %s %s in calm words and leaves the row as it was", async (status, code, title) => {
    const { onEnriched } = setup(makeAlert(), { handlers: { enrich: () => apiError(status, code) } });

    await userEvent.click(screen.getByRole("button", { name: "Look up address for rule NET-001" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(title);
    expect(screen.getByText("Not looked up")).toBeInTheDocument();
    expect(lookupButton()).toBeInTheDocument();
    expect(onEnriched).not.toHaveBeenCalled();
  });

  it("says how long to wait when the server asks for a pause", async () => {
    setup(makeAlert(), {
      handlers: { enrich: () => apiError(429, "rate_limited", "Slow down.", { "Retry-After": "30" }) },
    });

    await userEvent.click(screen.getByRole("button", { name: "Look up address for rule NET-001" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Try again in 30 seconds");
  });

  it("shows the API's own words for a failure it has none for", async () => {
    setup(makeAlert(), { handlers: { enrich: () => apiError(500, "internal_error", "The lookup service crashed.") } });

    await userEvent.click(screen.getByRole("button", { name: "Look up address for rule NET-001" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("The lookup service crashed.");
  });

  it("clears its error when the next lookup works", async () => {
    let calls = 0;
    setup(makeAlert(), {
      handlers: {
        enrich: () => {
          calls += 1;
          return calls === 1
            ? apiError(500, "internal_error", "The lookup service crashed.")
            : makeAlert({ enrichment: makeCompletedEnrichment() });
        },
      },
    });

    await userEvent.click(screen.getByRole("button", { name: "Look up address for rule NET-001" }));
    await screen.findByRole("alert");
    await userEvent.click(screen.getByRole("button", { name: "Look up address for rule NET-001" }));

    expect(await screen.findByText("Risk score 72 of 100")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("goes back to what the list says once the list is read again", async () => {
    networkApi({ enrich: () => makeAlert({ enrichment: makeCompletedEnrichment() }) });
    const onEnriched = vi.fn();
    const { rerender } = render(
      <ul>
        <AlertRow alert={makeAlert()} enrichmentEnabled onEnriched={onEnriched} />
      </ul>,
    );

    await userEvent.click(screen.getByRole("button", { name: "Look up address for rule NET-001" }));
    await screen.findByText("Risk score 72 of 100");
    rerender(
      <ul>
        <AlertRow
          alert={makeAlert({ enrichment: makeEnrichment({ status: "pending", address: SCANNER_IP }) })}
          enrichmentEnabled
          onEnriched={onEnriched}
        />
      </ul>,
    );

    expect(screen.getByText("Looking up")).toBeInTheDocument();
    expect(screen.queryByText("Risk score 72 of 100")).not.toBeInTheDocument();
  });
});
