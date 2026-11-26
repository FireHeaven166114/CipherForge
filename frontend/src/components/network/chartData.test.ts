import { describe, expect, it } from "vitest";

import type { ProtocolStat } from "../../types/network";
import { protocolSlices, rankProtocols, talkerItems } from "./chartData";

const stat = (protocol: string, packets: number, bytes = packets * 10): ProtocolStat => ({
  protocol,
  packets,
  bytes,
});

describe("rankProtocols", () => {
  it("puts the busiest protocol first, leaves out silent ones and keeps the input as it was", () => {
    const input = [stat("udp", 5), stat("tcp", 30), stat("icmp", 0), stat("arp", 5, 900)];
    const ranked = rankProtocols(input);

    expect(ranked.map((entry) => entry.protocol)).toEqual(["tcp", "arp", "udp"]);
    expect(input.map((entry) => entry.protocol)).toEqual(["udp", "tcp", "icmp", "arp"]);
  });

  it("orders protocols that tie on packets and bytes by name, so the order is stable", () => {
    const ranked = rankProtocols([stat("udp", 5, 50), stat("tcp", 5, 50)]);
    expect(ranked.map((entry) => entry.protocol)).toEqual(["tcp", "udp"]);
  });
});

describe("protocolSlices", () => {
  it("makes one slice per protocol with a name, a value and a shape of its own", () => {
    const slices = protocolSlices([stat("tcp", 30), stat("icmpv6", 10), stat("proto-47", 2)]);

    expect(slices.map((slice) => [slice.label, slice.value])).toEqual([
      ["TCP", 30],
      ["ICMPv6", 10],
      ["Protocol 47", 2],
    ]);
    expect(new Set(slices.map((slice) => slice.symbol)).size).toBe(3);
  });

  it("gathers the smallest protocols into one slice once the palette is used up", () => {
    const many = Array.from({ length: 8 }, (_, index) => stat(`p${index}`, 80 - index * 10));
    const slices = protocolSlices(many);

    expect(slices).toHaveLength(6);
    expect(slices.slice(0, 5).map((slice) => slice.key)).toEqual(["p0", "p1", "p2", "p3", "p4"]);
    expect(slices[5]).toMatchObject({ key: "other", label: "Other protocols", value: 30 + 20 + 10 });
  });

  it("does not gather anything when the protocols fit the palette exactly", () => {
    const six = Array.from({ length: 6 }, (_, index) => stat(`p${index}`, 60 - index));
    const slices = protocolSlices(six);

    expect(slices).toHaveLength(6);
    expect(slices.some((slice) => slice.key === "other")).toBe(false);
  });

  it("returns no slices for no packets", () => {
    expect(protocolSlices([])).toEqual([]);
    expect(protocolSlices([stat("tcp", 0)])).toEqual([]);
  });
});

describe("talkerItems", () => {
  it("counts bytes, the figure the API ranks by, and carries no risk", () => {
    expect(talkerItems([{ address: "203.0.113.45", packets: 4, bytes: 4096 }])).toEqual([
      { key: "203.0.113.45", label: "203.0.113.45", count: 4096, maxRisk: null },
    ]);
  });
});
