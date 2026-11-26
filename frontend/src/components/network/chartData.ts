import { protocolLabel } from "../../features/network/labels";
import type { ProtocolStat, TalkerStat } from "../../types/network";
import type { DonutSlice } from "../charts/Donut";
import type { HBarItem } from "../charts/HBarList";

interface Look {
  stroke: string;
  swatch: string;
  /** A shape that tells the slices apart without colour. */
  symbol: string;
}

// Written out in full, so the build finds every class.
const LOOKS: readonly Look[] = [
  { stroke: "stroke-cipher", swatch: "bg-cipher", symbol: "●" },
  { stroke: "stroke-arc", swatch: "bg-arc", symbol: "■" },
  { stroke: "stroke-pulse", swatch: "bg-pulse", symbol: "▲" },
  { stroke: "stroke-ember", swatch: "bg-ember", symbol: "◆" },
  { stroke: "stroke-low", swatch: "bg-low", symbol: "○" },
  { stroke: "stroke-med", swatch: "bg-med", symbol: "□" },
];

const OTHER: Look = { stroke: "stroke-ink-400", swatch: "bg-ink-400", symbol: "…" };

/** The protocols seen, busiest first by packets. */
export function rankProtocols(protocols: readonly ProtocolStat[]): ProtocolStat[] {
  return protocols
    .filter((entry) => entry.packets > 0)
    .sort((a, b) => b.packets - a.packets || b.bytes - a.bytes || a.protocol.localeCompare(b.protocol));
}

/** One slice per protocol by packets. Past the palette, the smallest are gathered into one. */
export function protocolSlices(protocols: readonly ProtocolStat[]): DonutSlice[] {
  const ranked = rankProtocols(protocols);
  const gather = ranked.length > LOOKS.length;
  const named = gather ? ranked.slice(0, LOOKS.length - 1) : ranked;
  const slices: DonutSlice[] = named.map((entry, index) => ({
    key: entry.protocol,
    label: protocolLabel(entry.protocol),
    value: entry.packets,
    ...(LOOKS[index] ?? OTHER),
  }));
  if (gather) {
    slices.push({
      key: "other",
      label: "Other protocols",
      value: ranked.slice(named.length).reduce((sum, entry) => sum + entry.packets, 0),
      ...OTHER,
    });
  }
  return slices;
}

/** The addresses that moved the most data. The bars count bytes, which is how the API ranks them. */
export function talkerItems(talkers: readonly TalkerStat[]): HBarItem[] {
  return talkers.map((talker) => ({
    key: talker.address,
    label: talker.address,
    count: talker.bytes,
    maxRisk: null,
  }));
}
