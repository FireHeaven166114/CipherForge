export type PaletteAction =
  | { kind: "go"; to: string }
  | { kind: "investigate"; indicator: string }
  | { kind: "search"; query: string }
  | { kind: "effects" };

export interface PaletteItem {
  id: string;
  label: string;
  /** Small text at the right of the row: what it does, or the shortcut that does the same. */
  hint: string;
  action: PaletteAction;
}

const PAGES = [
  { id: "go-overview", label: "Go to Overview", hint: "G then O", to: "/", words: "home dashboard deck" },
  {
    id: "go-investigate",
    label: "Go to Investigate",
    hint: "G then I",
    to: "/investigate",
    words: "lookup check scan",
  },
  {
    id: "go-indicators",
    label: "Go to Indicators",
    hint: "G then L",
    to: "/indicators",
    words: "list table ioc stored",
  },
  {
    id: "go-network",
    label: "Go to Network",
    hint: "G then N",
    to: "/network",
    words: "monitoring capture packets pcap traffic flows",
  },
  {
    id: "go-files",
    label: "Go to Files",
    hint: "G then F",
    to: "/files",
    words: "encrypted share upload download link secure",
  },
  {
    id: "go-status",
    label: "Go to System status",
    hint: "G then S",
    to: "/status",
    words: "health api ready uptime",
  },
] as const;

interface EffectsInfo {
  enabled: boolean;
  /** The operating system asks for reduced motion, so the switch is not offered. */
  locked: boolean;
}

/**
 * What the command palette offers for the text typed so far. Anything typed can be investigated
 * or searched for; the pages and the effects switch are filtered by the words typed.
 */
export function buildPaletteItems(query: string, effects: EffectsInfo): PaletteItem[] {
  const text = query.trim();
  const items: PaletteItem[] = [];

  if (text !== "") {
    items.push(
      {
        id: "investigate",
        label: `Investigate “${text}”`,
        hint: "Ask the providers",
        action: { kind: "investigate", indicator: text },
      },
      {
        id: "search",
        label: `Search indicators for “${text}”`,
        hint: "Stored indicators",
        action: { kind: "search", query: text },
      },
    );
  }

  const needles = text.toLowerCase().split(/\s+/).filter(Boolean);
  const matches = (haystack: string) => needles.every((needle) => haystack.toLowerCase().includes(needle));

  for (const page of PAGES) {
    if (matches(`${page.label} ${page.words}`)) {
      items.push({ id: page.id, label: page.label, hint: page.hint, action: { kind: "go", to: page.to } });
    }
  }

  if (!effects.locked) {
    const label = effects.enabled ? "Turn visual effects off" : "Turn visual effects on";
    if (matches(`${label} motion animation fx`)) {
      items.push({ id: "effects", label, hint: "This browser", action: { kind: "effects" } });
    }
  }

  return items;
}
