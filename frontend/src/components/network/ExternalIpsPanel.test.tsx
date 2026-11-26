import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import {
  HOST_IP,
  SCANNER_IP,
  makeCompletedEnrichment,
  makeEnrichment,
  makeExternalIp,
  makeSessionDetail,
} from "../../test/networkFixtures";
import type { EnrichmentSummary, ExternalIp } from "../../types/network";
import ExternalIpsPanel from "./ExternalIpsPanel";

function renderPanel(addresses: ExternalIp[] = [makeExternalIp()], summary: Partial<EnrichmentSummary> = {}) {
  const session = makeSessionDetail({
    external_ips: addresses,
    enrichment: { ...makeSessionDetail().enrichment, ...summary },
  });
  return render(<ExternalIpsPanel session={session} />);
}

function card(address: string): HTMLElement {
  const item = screen.getByRole("heading", { level: 3, name: address }).closest("li");
  if (item === null) throw new Error(`No card for ${address}`);
  return item;
}

const factOf = (entry: HTMLElement, label: string) => within(entry).getByText(label).nextElementSibling;

function manyAddresses(count: number): ExternalIp[] {
  return Array.from({ length: count }, (_, index) => makeExternalIp({ address: `198.51.100.${index + 1}` }));
}

describe("ExternalIpsPanel: the addresses", () => {
  it("lists a public address with when it was seen, how much traffic, and what it did", () => {
    renderPanel();

    expect(screen.getByRole("heading", { level: 2, name: "External IP addresses" })).toBeInTheDocument();
    const entry = card(SCANNER_IP);
    expect(factOf(entry, "First seen")).toHaveTextContent("20-05-2026 02:00:05 PM IST");
    expect(factOf(entry, "Last seen")).toHaveTextContent("20-05-2026 02:00:50 PM IST");
    expect(factOf(entry, "Packets")).toHaveTextContent(/^40$/);
    expect(factOf(entry, "Data")).toHaveTextContent("2.34 KB");
  });

  it("gives the cards one column that can shrink, so a long word cannot push the page sideways", () => {
    renderPanel();

    expect(screen.getByRole("list", { name: "External IP addresses" })).toHaveClass("grid-cols-1");
  });

  it("says in words whether traffic was sent to the address and whether it raised an alert", () => {
    renderPanel([
      makeExternalIp({ address: "198.51.100.1", sent_to: false, alerted: true }),
      makeExternalIp({ address: "198.51.100.2", sent_to: true, alerted: false }),
    ]);

    expect(factOf(card("198.51.100.1"), "Traffic sent to it")).toHaveTextContent(/^No$/);
    expect(factOf(card("198.51.100.1"), "Raised an alert")).toHaveTextContent(/^Yes$/);
    expect(factOf(card("198.51.100.2"), "Traffic sent to it")).toHaveTextContent(/^Yes$/);
    expect(factOf(card("198.51.100.2"), "Raised an alert")).toHaveTextContent(/^No$/);
  });

  it("shows the ports, protocols and peers as plain labelled lists", () => {
    renderPanel();
    const entry = card(SCANNER_IP);

    const ports = within(entry).getByRole("list", { name: `Ports seen with ${SCANNER_IP}` });
    expect(within(ports).getAllByRole("listitem").map((item) => item.textContent)).toEqual(["22", "80", "443"]);
    const protocols = within(entry).getByRole("list", { name: `Protocols seen with ${SCANNER_IP}` });
    expect(within(protocols).getAllByRole("listitem").map((item) => item.textContent)).toEqual(["TCP"]);
    const peers = within(entry).getByRole("list", { name: `Peers of ${SCANNER_IP}` });
    expect(within(peers).getAllByRole("listitem").map((item) => item.textContent)).toEqual([HOST_IP]);
  });

  it("writes protocols as an analyst would", () => {
    renderPanel([makeExternalIp({ protocols: ["icmpv6", "proto-47", "udp"] })]);

    const protocols = within(card(SCANNER_IP)).getByRole("list", { name: `Protocols seen with ${SCANNER_IP}` });
    expect(within(protocols).getAllByRole("listitem").map((item) => item.textContent)).toEqual([
      "ICMPv6",
      "Protocol 47",
      "UDP",
    ]);
  });

  it("leaves out the rows that have nothing to list", () => {
    renderPanel([makeExternalIp({ ports: [], protocols: [], peers: [] })]);
    const entry = card(SCANNER_IP);

    expect(within(entry).queryByText("Ports")).not.toBeInTheDocument();
    expect(within(entry).queryByText("Protocols")).not.toBeInTheDocument();
    expect(within(entry).queryByText("Peers")).not.toBeInTheDocument();
  });

  it("shortens a long list of ports and says how many are not shown", () => {
    renderPanel([makeExternalIp({ ports: Array.from({ length: 25 }, (_, index) => 1000 + index) })]);

    const ports = within(card(SCANNER_IP)).getByRole("list", { name: `Ports seen with ${SCANNER_IP}` });
    expect(within(ports).getAllByRole("listitem")).toHaveLength(21);
    expect(within(ports).getByText("+5 more")).toBeInTheDocument();
  });

  it("says 'Not recorded' for what the server did not record, rather than a made-up zero", () => {
    renderPanel([makeExternalIp({ first_seen: null, last_seen: null, packets: null, bytes: null })]);
    const entry = card(SCANNER_IP);

    for (const label of ["First seen", "Last seen", "Packets", "Data"]) {
      expect(factOf(entry, label)).toHaveTextContent("Not recorded");
    }
  });

  it("keeps the order the server gave", () => {
    renderPanel([
      makeExternalIp({ address: "198.51.100.9" }),
      makeExternalIp({ address: "198.51.100.1" }),
      makeExternalIp({ address: "198.51.100.5" }),
    ]);

    const list = screen.getByRole("list", { name: "External IP addresses" });
    expect(within(list).getAllByRole("heading", { level: 3 }).map((heading) => heading.textContent)).toEqual([
      "198.51.100.9",
      "198.51.100.1",
      "198.51.100.5",
    ]);
  });

  it("says so when no public address was seen", () => {
    renderPanel([]);

    expect(screen.getByText("No public addresses were seen in this session's traffic.")).toBeInTheDocument();
    expect(screen.queryByRole("list", { name: "External IP addresses" })).not.toBeInTheDocument();
    expect(screen.queryByRole("navigation", { name: "External IP addresses pagination" })).not.toBeInTheDocument();
  });

  it("shows ten addresses at a time and pages through the rest", async () => {
    renderPanel(manyAddresses(12));
    const list = screen.getByRole("list", { name: "External IP addresses" });
    expect(within(list).getAllByRole("heading", { level: 3 })).toHaveLength(10);
    expect(screen.getByText("Showing 1–10 of 12")).toBeInTheDocument();
    expect(screen.getByRole("navigation", { name: "External IP addresses pagination" })).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Next" }));

    expect(within(list).getAllByRole("heading", { level: 3 }).map((heading) => heading.textContent)).toEqual([
      "198.51.100.11",
      "198.51.100.12",
    ]);
    expect(screen.getByText("Showing 11–12 of 12")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Next" })).toBeDisabled();

    await userEvent.click(screen.getByRole("button", { name: "Previous" }));
    expect(within(list).getAllByRole("heading", { level: 3 })).toHaveLength(10);
  });

  it("shows no further page for ten addresses or fewer", () => {
    renderPanel(manyAddresses(10));

    expect(screen.getByText("Showing 1–10 of 10")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Previous" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Next" })).toBeDisabled();
  });
});

describe("ExternalIpsPanel: what is known about each address", () => {
  it("shows a score and the providers only for an address that was looked up", () => {
    renderPanel([
      makeExternalIp({ address: "198.51.100.1", enrichment: makeCompletedEnrichment({ address: "198.51.100.1" }) }),
      makeExternalIp({ address: "198.51.100.2" }),
    ]);

    const looked = card("198.51.100.1");
    expect(within(looked).getByText("Risk score 72 of 100")).toBeInTheDocument();
    expect(within(looked).getByText("AbuseIPDB: Answered, verdict malicious")).toBeInTheDocument();
    const notLooked = card("198.51.100.2");
    expect(within(notLooked).getByText("Not looked up")).toBeInTheDocument();
    expect(within(notLooked).queryByText(/Risk score/)).not.toBeInTheDocument();
    expect(
      within(notLooked).getByText("This address has not been looked up. Nothing was sent to any provider."),
    ).toBeInTheDocument();
  });

  it("does not repeat the address inside the lookup detail", () => {
    renderPanel([makeExternalIp({ enrichment: makeCompletedEnrichment() })]);

    expect(screen.getAllByText(SCANNER_IP)).toHaveLength(1);
  });

  it("never reads a lookup without data as a clean result", () => {
    renderPanel([
      makeExternalIp({
        enrichment: makeCompletedEnrichment({ risk_score: null, classification: null, assessed: false }),
      }),
    ]);

    expect(
      within(card(SCANNER_IP)).getByText("No provider returned data. This is not evidence the address is safe."),
    ).toBeInTheDocument();
    expect(within(card(SCANNER_IP)).queryByText(/Risk score/)).not.toBeInTheDocument();
  });

  it("shows why a lookup failed or could not be made", () => {
    renderPanel([
      makeExternalIp({
        address: "198.51.100.1",
        enrichment: makeEnrichment({ status: "failed", message: "The provider timed out." }),
      }),
      makeExternalIp({ address: "198.51.100.2", enrichment: makeEnrichment({ status: "skipped_budget" }) }),
    ]);

    expect(within(card("198.51.100.1")).getByText("Lookup failed")).toBeInTheDocument();
    expect(within(card("198.51.100.1")).getByText("The provider timed out.")).toBeInTheDocument();
    expect(within(card("198.51.100.2")).getByText("Lookup limit reached")).toBeInTheDocument();
  });
});

describe("ExternalIpsPanel: the summary and what is looked up", () => {
  it("states what is looked up: public addresses once, never every packet and never private ones", () => {
    renderPanel();

    expect(
      screen.getByText(
        /Only deduplicated public addresses are ever looked up, never every packet, and never private addresses\./,
      ),
    ).toBeInTheDocument();
    expect(screen.getByText(/Private, loopback and other non-public addresses are not listed here/)).toBeInTheDocument();
  });

  it("summarises the lookups while enrichment is on", () => {
    renderPanel([makeExternalIp()], { total: 12, completed: 5, pending: 2, failed: 1, unavailable: 1, skipped: 3 });

    const summary = screen.getByLabelText("Lookup summary");
    const row = (label: string) => within(summary).getByText(label).nextElementSibling;
    expect(row("Public addresses")).toHaveTextContent("12");
    expect(row("Looked up")).toHaveTextContent("5");
    expect(row("Pending")).toHaveTextContent("2");
    expect(row("Failed")).toHaveTextContent("1");
    expect(row("Unavailable")).toHaveTextContent("1");
    expect(row("Skipped or not looked up")).toHaveTextContent("3");
    expect(screen.queryByText("External enrichment is switched off on this server")).not.toBeInTheDocument();
  });

  it("groups large counts", () => {
    renderPanel([makeExternalIp()], { total: 1234 });

    expect(screen.getByText("Public addresses").nextElementSibling).toHaveTextContent("1,234");
  });

  it("explains how addresses are chosen and that the list is capped", () => {
    renderPanel();

    expect(screen.getByText(/alerted ones first/)).toBeInTheDocument();
    expect(screen.getByText(/At most 100 addresses are listed/)).toBeInTheDocument();
  });

  it("says plainly that nothing is looked up while enrichment is off, and still lists the addresses", () => {
    renderPanel([makeExternalIp()], { enabled: false });

    expect(screen.getByRole("note")).toHaveTextContent("External enrichment is switched off on this server");
    expect(screen.getByRole("note")).toHaveTextContent("none is looked up or sent to any provider");
    expect(screen.queryByLabelText("Lookup summary")).not.toBeInTheDocument();
    expect(card(SCANNER_IP)).toBeInTheDocument();
  });
});
