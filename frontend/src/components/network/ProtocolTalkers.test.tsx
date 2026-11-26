import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { ProtocolStat, TalkerStat } from "../../types/network";
import ProtocolPanel from "./ProtocolPanel";
import TopTalkers from "./TopTalkers";

const protocol = (name: string, packets: number, bytes: number): ProtocolStat => ({
  protocol: name,
  packets,
  bytes,
});

describe("ProtocolPanel", () => {
  const protocols = [protocol("udp", 10, 1500), protocol("tcp", 30, 2400), protocol("icmpv6", 10, 800)];

  it("lists each protocol with its packets and its share, busiest first", () => {
    render(<ProtocolPanel protocols={protocols} />);

    expect(screen.getByRole("heading", { name: "Protocol distribution" })).toBeInTheDocument();
    const legend = screen.getByRole("list", { name: "Packets by protocol" });
    expect(within(legend).getAllByRole("group").map((entry) => entry.getAttribute("aria-label"))).toEqual([
      "TCP: 30 packets, 60%",
      "UDP: 10 packets, 20%",
      "ICMPv6: 10 packets, 20%",
    ]);
  });

  it("gives the same figures as a table, with sizes in units", () => {
    render(<ProtocolPanel protocols={protocols} />);

    const table = screen.getByRole("table", { name: "Packets and data by protocol", hidden: true });
    const rows = within(table).getAllByRole("row", { hidden: true });
    expect(rows.map((row) => row.textContent)).toEqual([
      "ProtocolPacketsData",
      "TCP302.34 KB",
      "UDP101.46 KB",
      "ICMPv610800 B",
    ]);
    expect(screen.getByText(/Table view/)).toBeInTheDocument();
  });

  it("says so when no packet has been analysed, and offers no empty table", () => {
    render(<ProtocolPanel protocols={[]} />);

    expect(screen.getByText("No packets have been analysed yet.")).toBeInTheDocument();
    expect(screen.queryByRole("table", { hidden: true })).not.toBeInTheDocument();
  });

  it("groups the smallest protocols into one entry when there are too many to tell apart", () => {
    const many = Array.from({ length: 9 }, (_, index) => protocol(`proto-${index + 100}`, 90 - index * 10, 100));
    render(<ProtocolPanel protocols={many} />);

    const legend = screen.getByRole("list", { name: "Packets by protocol" });
    expect(within(legend).getAllByRole("group")).toHaveLength(6);
    expect(within(legend).getByText("Other protocols")).toBeInTheDocument();
    const table = screen.getByRole("table", { hidden: true });
    expect(within(table).getAllByRole("row", { hidden: true })).toHaveLength(10);
  });
});

describe("TopTalkers", () => {
  const sources: TalkerStat[] = [
    { address: "203.0.113.45", packets: 40, bytes: 2400 },
    { address: "198.51.100.7", packets: 3, bytes: 180 },
  ];
  const destinations: TalkerStat[] = [{ address: "192.0.2.10", packets: 43, bytes: 2580 }];

  it("ranks source and destination addresses in lists of their own", () => {
    render(<TopTalkers sources={sources} destinations={destinations} truncated={false} />);

    expect(screen.getByRole("heading", { name: "Top source IPs" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Top destination IPs" })).toBeInTheDocument();
    const sourceList = screen.getByRole("list", { name: "Top source IPs by bytes" });
    expect(within(sourceList).getAllByRole("listitem").map((item) => item.textContent)).toEqual([
      expect.stringContaining("203.0.113.45: 2400 bytes"),
      expect.stringContaining("198.51.100.7: 180 bytes"),
    ]);
    const destinationList = screen.getByRole("list", { name: "Top destination IPs by bytes" });
    expect(within(destinationList).getByText(/192\.0\.2\.10/)).toBeInTheDocument();
  });

  it("says in words that the bars count bytes, and gives packets and sizes in a table", () => {
    render(<TopTalkers sources={sources} destinations={destinations} truncated={false} />);

    expect(screen.getByText(/Ranked by bytes/)).toBeInTheDocument();
    const table = screen.getByRole("table", { name: "Top source IPs, with packets and data", hidden: true });
    expect(within(table).getAllByRole("row", { hidden: true }).map((row) => row.textContent)).toEqual([
      "AddressPacketsData",
      "203.0.113.45402.34 KB",
      "198.51.100.73180 B",
    ]);
  });

  it("says so when there is nothing to rank yet", () => {
    render(<TopTalkers sources={[]} destinations={[]} truncated={false} />);

    expect(screen.getByText("No source addresses yet.")).toBeInTheDocument();
    expect(screen.getByText("No destination addresses yet.")).toBeInTheDocument();
    expect(screen.queryByRole("table", { hidden: true })).not.toBeInTheDocument();
  });

  it("shows the ten busiest addresses and no more", () => {
    const crowd = Array.from({ length: 12 }, (_, index) => ({
      address: `198.51.100.${index + 1}`,
      packets: 100 - index,
      bytes: 10_000 - index * 100,
    }));
    render(<TopTalkers sources={crowd} destinations={[]} truncated={false} />);

    const list = screen.getByRole("list", { name: "Top source IPs by bytes" });
    expect(within(list).getAllByRole("listitem")).toHaveLength(10);
    expect(within(list).queryByText(/198\.51\.100\.11:/)).not.toBeInTheDocument();
  });

  it("warns that the lists can undercount when the monitor dropped quiet addresses", () => {
    const { rerender } = render(<TopTalkers sources={sources} destinations={destinations} truncated />);

    const note = screen.getByRole("note");
    expect(note).toHaveTextContent("These lists may undercount");
    expect(note).toHaveTextContent("An address missing here may still have appeared in the traffic.");

    rerender(<TopTalkers sources={sources} destinations={destinations} truncated={false} />);
    expect(screen.queryByRole("note")).not.toBeInTheDocument();
  });
});
