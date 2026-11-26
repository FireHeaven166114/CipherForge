import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { makeSessionDetail } from "../../test/networkFixtures";
import type { SessionDetail } from "../../types/network";
import SessionSummary from "./SessionSummary";

function setup(session: SessionDetail = makeSessionDetail()) {
  const onDelete = vi.fn();
  render(<SessionSummary session={session} onDelete={onDelete} />);
  return { onDelete, session };
}

function tile(label: string): HTMLElement {
  const box = screen.getByText(label, { selector: "dt" }).parentElement;
  if (box === null) throw new Error(`No tile for ${label}`);
  return box;
}

function fact(label: string): HTMLElement {
  const value = screen.getByText(label, { selector: "dt" }).nextElementSibling;
  if (!(value instanceof HTMLElement)) throw new Error(`No fact for ${label}`);
  return value;
}

function counter(label: string): HTMLElement {
  const row = screen.getByText(label).closest("div");
  if (row === null) throw new Error(`No counter for ${label}`);
  return row;
}

describe("SessionSummary", () => {
  it("shows the headline figures of a finished capture file", () => {
    setup();

    expect(screen.getByRole("heading", { name: "Session summary" })).toBeInTheDocument();
    expect(tile("Duration")).toHaveTextContent("1 min 30 s");
    expect(tile("Packets")).toHaveTextContent("40");
    expect(tile("Data")).toHaveTextContent("2.34 KB");
    expect(tile("Active flows")).toHaveTextContent("0");
    expect(tile("Flows seen")).toHaveTextContent("40");
    expect(tile("Alerts")).toHaveTextContent("1");
    expect(tile("Packets dropped")).toHaveTextContent("0");
    expect(screen.getByText("Completed")).toBeInTheDocument();
  });

  it("groups big numbers and writes sizes in units", () => {
    setup(makeSessionDetail({ packets_total: 1234567, bytes_total: 5_000_000, duration_seconds: 7384 }));

    expect(tile("Packets")).toHaveTextContent("1,234,567");
    expect(tile("Data")).toHaveTextContent("4.77 MB");
    expect(tile("Duration")).toHaveTextContent("2 h 03 min");
  });

  it("gives every time in IST, with the capture start first", () => {
    setup();

    expect(fact("Capture started")).toHaveTextContent("20-05-2026 02:00:00 PM IST");
    expect(fact("Capture ended")).toHaveTextContent("20-05-2026 02:01:30 PM IST");
    expect(fact("First packet")).toHaveTextContent("20-05-2026 02:00:05 PM IST");
    expect(fact("Last packet")).toHaveTextContent("20-05-2026 02:00:50 PM IST");
  });

  it("names the file a capture was read from, as plain text", () => {
    setup(makeSessionDetail({ source_label: '<b onmouseover="x()">evil.pcap</b>' }));

    expect(fact("Source")).toHaveTextContent('Capture file: <b onmouseover="x()">evil.pcap</b>');
    expect(fact("Source").querySelector("b")).toBeNull();
  });

  it("names the interface of a live capture that is still running", () => {
    setup(
      makeSessionDetail({
        source_kind: "live",
        interface: "eth0",
        source_label: null,
        status: "running",
        ended_at: null,
        duration_seconds: 12.4,
      }),
    );

    expect(fact("Source")).toHaveTextContent("Live capture: eth0");
    expect(fact("Capture ended")).toHaveTextContent("Still running");
    expect(tile("Duration")).toHaveTextContent("12 s");
    expect(screen.getByText("Running")).toBeInTheDocument();
  });

  it("says that no packet has been seen yet instead of showing an empty time", () => {
    setup(makeSessionDetail({ first_packet_at: null, last_packet_at: null }));

    expect(fact("First packet")).toHaveTextContent("No packet yet");
    expect(fact("Last packet")).toHaveTextContent("No packet yet");
  });

  it("lists the alerts by rule, and leaves the line out when there are none", () => {
    const { unmount } = render(
      <SessionSummary
        session={makeSessionDetail({ alerts_by_rule: { "NET-003": 2, "NET-001": 1, "NET-002": 0 } })}
        onDelete={vi.fn()}
      />,
    );
    const chips = screen.getAllByRole("listitem").map((item) => item.textContent);
    expect(chips).toEqual(["NET-001: 1", "NET-003: 2"]);
    unmount();

    render(<SessionSummary session={makeSessionDetail({ alerts_by_rule: {} })} onDelete={vi.fn()} />);
    expect(screen.queryByText("Alerts by rule")).not.toBeInTheDocument();
  });

  it("explains what a dropped packet means when the monitor dropped some", () => {
    setup(makeSessionDetail({ packets_dropped: 12 }));

    expect(tile("Packets dropped")).toHaveTextContent("12");
    expect(tile("Packets dropped")).toHaveTextContent("Some traffic was not analysed");
    const row = counter("Packets dropped by the monitor");
    expect(row).toHaveTextContent("12");
    expect(row).toHaveTextContent("bounded queue overflowed");
    expect(row).toHaveTextContent("not the operating system's drop count");
  });

  it("does not take zero dropped packets as proof that nothing was lost", () => {
    setup();

    const row = counter("Packets dropped by the monitor");
    expect(row).toHaveTextContent("zero does not prove none were lost");
    expect(tile("Packets dropped")).not.toHaveTextContent("Some traffic was not analysed");
  });

  it("surfaces every counter that says what the totals leave out", () => {
    setup(
      makeSessionDetail({
        non_ip_packets: 3,
        malformed_packets: 2,
        flows_evicted: 5,
        flows_stored: 33,
        flows_not_stored: 7,
        alerts_suppressed: 4,
        alerts_lost: 1,
        talkers_truncated: true,
      }),
    );

    const section = screen.getByRole("heading", { name: "What the totals leave out" }).closest("section");
    expect(section).not.toBeNull();
    const inside = within(section as HTMLElement);
    expect(inside.getAllByRole("term")).toHaveLength(9);
    const expected: [string, string][] = [
      ["Non-IP packets", "3"],
      ["Malformed packets", "2"],
      ["Flows closed early", "5"],
      ["Flows stored", "33"],
      ["Flows not stored", "7"],
      ["Repeat alerts suppressed", "4"],
      ["Alerts lost", "1"],
      ["Top talkers truncated", "Yes"],
    ];
    for (const [label, value] of expected) {
      expect(counter(label)).toHaveTextContent(value);
    }
    expect(counter("Flows not stored")).toHaveTextContent("counted in the totals but are not in the flows table");
    expect(counter("Repeat alerts suppressed")).toHaveTextContent("cooling down");
  });

  it("shows why a session ended early, in calm words", () => {
    setup(
      makeSessionDetail({
        status: "failed",
        error_code: "capture_failed",
        message: "The adapter was removed.",
        ended_at: null,
      }),
    );

    const note = screen.getByRole("note");
    expect(note).toHaveTextContent("Capture stopped by an error");
    expect(note).toHaveTextContent("Packet capture stopped because of an error.");
    expect(note).toHaveTextContent("The adapter was removed.");
  });

  it("shows no note for a session that ended well", () => {
    setup();
    expect(screen.queryByRole("note")).not.toBeInTheDocument();
  });

  it("hands the session to the delete flow when the button is pressed", async () => {
    const { onDelete, session } = setup();

    await userEvent.click(screen.getByRole("button", { name: "Delete session" }));

    expect(onDelete).toHaveBeenCalledWith(session);
  });

  it("does not delete a session that is still being filled", async () => {
    const { onDelete } = setup(makeSessionDetail({ status: "running", ended_at: null }));

    const button = screen.getByRole("button", { name: "Delete session" });
    expect(button).toHaveAttribute("aria-disabled", "true");
    expect(button).toHaveAccessibleDescription("A session cannot be deleted while it is running.");
    await userEvent.click(button);

    expect(onDelete).not.toHaveBeenCalled();
  });
});
