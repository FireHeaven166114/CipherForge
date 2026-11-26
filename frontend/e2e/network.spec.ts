import { readFile } from "node:fs/promises";

import type { APIRequestContext, Locator, Page } from "@playwright/test";

import type { Flow, NetworkStatus, SessionDetail } from "../src/types/network";
import {
  CLASSIFICATION_LABELS,
  countRequests,
  deleteViaApi,
  fetchIndicator,
  fetchIndicators,
  fetchOverview,
} from "./api";
import { expectAccessible, istText, statusOf, uniqueTag } from "./files-api";
import { expect, test as base } from "./fixtures";
import { ATTACKS, KINDS, LONG, TRAVERSAL_ID, expectInert, watchDialogs } from "./hostile";
import { expectFits, expectOnScreen, expectTextInPlace } from "./layout";
import {
  CAPTURE_NAME,
  CAPTURE_PATH,
  type FlowFact,
  type Packet,
  type Scan,
  type Segment,
  addressesOf,
  analyseSample,
  analyseViaApi,
  auditOfSession,
  buildCapture,
  byConversation,
  demoDatabaseBytes,
  endpointText,
  factOf,
  fetchAlerts,
  fetchFlows,
  fetchInterfaces,
  fetchRules,
  fetchSession,
  fetchSessions,
  fetchStatus,
  flagNames,
  flowName,
  flowsOf,
  isPublic,
  istOfSeconds,
  portScans,
  postCapture,
  readSample,
  refusalOf,
  removeSession,
  settledStatus,
  sizeText,
  startCapture,
  stopCapture,
  talkers,
} from "./network-api";
import { openNetwork } from "./open";
import { panel } from "./pages";
import { exactly, escapeRegExp, must } from "./text";

/**
 * Network monitoring, in a real browser against the real API: a capture file analysed offline, a
 * live capture, and what the screen does with data it cannot trust. The synthetic capture in
 * e2e/data is read byte by byte here, so every number the page shows is checked against the file
 * and not against the app's own reading of it. The API is used to set a test up, to clear it away
 * and as a second opinion; everything a person does is done in the page.
 */

/** A test that leaves no session, no capture and no new indicator behind. */
const test = base.extend<{ tidy: void }>({
  tidy: [
    async ({ page, request }, use) => {
      const sessionsBefore = new Set((await fetchSessions(request)).items.map((session) => session.id));
      const sample = await readSample();
      // 8.8.8.8 and 1.1.1.1 are in the demo data: only an address the run itself looked up is deleted.
      const knownBefore = new Map<string, boolean>();
      for (const address of addressesOf(sample.packets).filter(isPublic)) {
        knownBefore.set(address, (await indicatorIdOf(request, address)) !== undefined);
      }
      await use();

      // The page polls the session it shows, so it has to be gone before the session is.
      await page.goto("about:blank");
      const status = await fetchStatus(request);
      if (/^(starting|running|stopping)$/.test(status.state)) {
        await stopCapture(request);
        await settledStatus(request);
      }
      for (const session of (await fetchSessions(request)).items) {
        if (sessionsBefore.has(session.id)) continue;
        await expect
          .poll(async () => (await fetchSession(request, session.id)).enrichment.pending, { timeout: 20_000 })
          .toBe(0)
          .catch(() => undefined);
        await removeSession(request, session.id);
      }
      for (const [address, existed] of knownBefore) {
        if (existed) continue;
        const created = await indicatorIdOf(request, address);
        if (created !== undefined) await deleteViaApi(request, [created]);
      }
      expect(
        (await fetchSessions(request)).items.map((session) => session.id).sort(),
        "sessions the test left behind",
      ).toEqual([...sessionsBefore].sort());
      expect((await fetchStatus(request)).state, "a capture the test left running").not.toMatch(
        /^(starting|running|stopping)$/,
      );
    },
    { auto: true },
  ],
});

test.use({ reducedMotion: "reduce" });

// ---- What the page calls things ----------------------------------------------------------------

const SCREENS = [
  { width: 320, height: 640 },
  { width: 390, height: 844 },
  { width: 768, height: 1024 },
  { width: 1440, height: 900 },
] as const;

/** How the Network screen words what a provider answered. */
const PROVIDER_STATUS: Readonly<Record<string, string>> = {
  ok: "Answered",
  no_data: "No data",
  not_configured: "Not configured",
  unsupported: "Not supported",
  rate_limited: "Rate limited",
  error: "Error",
  not_queried: "Not queried",
};

const CLOSE_REASONS: Readonly<Record<string, string>> = {
  idle: "Idle",
  evicted: "Evicted",
  closed: "Closed",
  ended: "Session ended",
};

/** Nothing in the table of flows says what a packet carried: addresses, ports, counts and flags only. */
const FLOW_COLUMNS = [
  "Flow",
  "Protocol",
  "First seen",
  "Last seen",
  "Duration",
  "Packets out / in",
  "Data out / in",
  "TCP flags",
  "Ended by",
] as const;

/** The only things the API knows about a flow. */
const FLOW_FIELDS = [
  "bytes_in",
  "bytes_out",
  "close_reason",
  "dst_ip",
  "dst_port",
  "duration_seconds",
  "first_seen",
  "id",
  "last_seen",
  "packets_in",
  "packets_out",
  "protocol",
  "src_ip",
  "src_port",
  "tcp_flag_names",
  "tcp_flags",
] as const;

const FLOWS_PER_PAGE = 25;

/** Where private, loopback, link-local and documentation addresses start. No lookup may ever be made for one. */
const NEVER_LOOKED_UP = [
  "10.20.",
  "127.0.0.",
  "169.254.",
  "192.168.",
  "192.0.2.",
  "198.51.100.",
  "203.0.113.",
  "fd00:",
  "fe80:",
] as const;

// ---- Finding things on the page ----------------------------------------------------------------

/** The value beside a term of a definition list, such as the "Packets" of a session. */
function fact(scope: Locator, term: string): Locator {
  return scope
    .locator("dt", { hasText: new RegExp(`^${escapeRegExp(term)}\\s*$`) })
    .locator("xpath=following-sibling::dd[1]");
}

function uploadPanel(page: Page): Locator {
  return panel(page, "Analyse a capture file");
}

/** One alert of the session, found by its rule and the address it came from. */
function alertCard(page: Page, rule: string, source: string): Locator {
  return panel(page, "Alerts")
    .getByRole("list", { name: "Alerts", exact: true })
    .locator(":scope > li")
    .filter({ hasText: rule })
    .filter({ has: page.locator("dd", { hasText: exactly(source) }) });
}

function externalCard(page: Page, address: string): Locator {
  return panel(page, "External IP addresses")
    .getByRole("list", { name: "External IP addresses", exact: true })
    .locator(":scope > li")
    .filter({ has: page.getByRole("heading", { level: 3, name: address, exact: true }) });
}

function historyRow(page: Page, label: string): Locator {
  return panel(page, "Session history")
    .getByRole("row")
    .filter({ has: page.getByRole("rowheader", { name: label, exact: true }) });
}

async function openSession(page: Page, id: string): Promise<void> {
  await openNetwork(page, `?session=${id}`);
  await expect(panel(page, "Session summary")).toBeVisible();
}

/** The cells of the rows on show, as a sighted person reads them and without the clock-dependent "2 hours ago". */
function flowCells(flows: Locator): Promise<string[][]> {
  return flows.locator("tbody tr").evaluateAll((rows) =>
    rows.map((row) =>
      Array.from(row.children, (cell) => {
        const copy = cell.cloneNode(true) as Element;
        copy.querySelectorAll(".sr-only").forEach((hidden) => hidden.remove());
        const text = (copy.textContent ?? "").replace(/\s+/g, " ").trim();
        const time = /^\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2} [AP]M IST/.exec(text);
        return cell.querySelector("time") !== null && time !== null ? time[0] : text;
      }),
    ),
  );
}

/** Every row of the table of flows, page after page, as the cells read. */
async function readFlowTable(page: Page, total: number): Promise<string[][]> {
  const flows = panel(page, "Flows");
  const rows: string[][] = [];
  for (let start = 0; start < total; start += FLOWS_PER_PAGE) {
    const count = Math.min(FLOWS_PER_PAGE, total - start);
    await expect(flows.getByText(`Showing ${start + 1}–${start + count} of ${total}`)).toBeVisible();
    const earlier = start === 0 ? undefined : JSON.stringify(rows[start - FLOWS_PER_PAGE]);
    await expect
      .poll(async () => {
        const shown = await flowCells(flows);
        return shown.length === count && JSON.stringify(shown[0]) !== earlier;
      }, { message: `page ${start / FLOWS_PER_PAGE + 1} of the flows is on show` })
      .toBe(true);
    rows.push(...(await flowCells(flows)));
    if (start + FLOWS_PER_PAGE < total) await flows.getByRole("button", { name: "Next", exact: true }).click();
  }
  return rows;
}

// ---- What the file and the API say, worked out by hand ------------------------------------------

async function indicatorIdOf(request: APIRequestContext, value: string): Promise<string | undefined> {
  const found = await fetchIndicators(request, { q: value, limit: 10 });
  return found.items.find((item) => item.indicator_value === value)?.indicator_id;
}

interface Sample {
  packets: Packet[];
  nonIp: number;
  flows: FlowFact[];
  bytes: number;
  publicAddresses: string[];
  privateAddresses: string[];
}

async function sampleFacts(): Promise<Sample> {
  const { packets, nonIp } = await readSample();
  const addresses = addressesOf(packets);
  return {
    packets,
    nonIp,
    flows: flowsOf(packets),
    bytes: packets.reduce((sum, packet) => sum + packet.bytes, 0),
    publicAddresses: addresses.filter(isPublic),
    privateAddresses: addresses.filter((address) => !isPublic(address)),
  };
}

/** Times as whole milliseconds, so that two readings of one instant compare as equal. */
function inMilliseconds(flow: FlowFact): FlowFact {
  return { ...flow, first: Math.round(flow.first * 1000), last: Math.round(flow.last * 1000) };
}

/** The nine cells the table shows for a flow, from what the API says about it. */
function rowOf(flow: Flow): string[] {
  const flags = flow.tcp_flags === null ? "Not TCP" : flagNames(flow.tcp_flags).join(" ") || "None";
  return [
    `${endpointText(flow.src_ip, flow.src_port)} → ${endpointText(flow.dst_ip, flow.dst_port)}`,
    flow.protocol.toUpperCase(),
    istText(flow.first_seen),
    istText(flow.last_seen),
    `${flow.duration_seconds.toFixed(1)} s`,
    `${flow.packets_out} / ${flow.packets_in}`,
    `${sizeText(flow.bytes_out)} / ${sizeText(flow.bytes_in)}`,
    flags,
    CLOSE_REASONS[flow.close_reason] ?? flow.close_reason,
  ];
}

interface Answer {
  display_name: string;
  status: string;
  verdict: string | null;
}

/** The lines of "Provider answers": "VirusTotal: Answered, verdict malicious". */
function providerLines(providers: readonly Answer[]): string[] {
  return providers.map((provider) => {
    const label = PROVIDER_STATUS[provider.status] ?? provider.status;
    return provider.verdict ? `${provider.display_name}: ${label}, verdict ${provider.verdict}` : `${provider.display_name}: ${label}`;
  });
}

/** What the capture says about one public address, from the packets that came from it or went to it. */
function externalFacts(packets: readonly Packet[], address: string) {
  const involved = packets.filter((packet) => packet.src === address || packet.dst === address);
  const ports = new Set<number>();
  for (const packet of involved) {
    const port = packet.src === address ? packet.srcPort : packet.dstPort;
    if (port !== null) ports.add(port);
  }
  return {
    packets: involved.length,
    bytes: involved.reduce((sum, packet) => sum + packet.bytes, 0),
    first: Math.min(...involved.map((packet) => packet.seconds)),
    last: Math.max(...involved.map((packet) => packet.seconds)),
    sentTo: involved.some((packet) => packet.dst === address),
    ports: [...ports].sort((low, high) => low - high),
    protocols: [...new Set(involved.map((packet) => packet.protocol.toUpperCase()))],
    peers: [...new Set(involved.map((packet) => (packet.src === address ? packet.dst : packet.src)))],
  };
}

function scanSentence(scan: Scan, threshold: number, windowSeconds: number): string {
  const hosts = scan.targets.length === 1 ? "1 host" : `${scan.targets.length} hosts`;
  return (
    `${scan.source} tried ${scan.ports.length} different destination ports on ${hosts} within ${windowSeconds} seconds ` +
    `(threshold: ${threshold} ports), between ${istOfSeconds(scan.first)} and ${istOfSeconds(scan.last)}.`
  );
}

// ---- The capture file, read independently ------------------------------------------------------------

test("the sample capture holds the traffic the tests expect", async () => {
  const sample = await sampleFacts();
  expect(sample.packets, "IP packets").toHaveLength(72);
  expect(sample.nonIp, "frames without an IP header").toBe(1);
  expect(sample.flows, "conversations").toHaveLength(59);
  expect(sample.bytes, "bytes on the wire").toBe(4714);
  for (const [protocol, packets, bytes] of [
    ["tcp", 60, 3840],
    ["udp", 10, 790],
    ["icmp", 2, 84],
  ] as const) {
    const ofKind = sample.packets.filter((packet) => packet.protocol === protocol);
    expect([protocol, ofKind.length, ofKind.reduce((sum, packet) => sum + packet.bytes, 0)]).toEqual([
      protocol,
      packets,
      bytes,
    ]);
  }

  expect(sample.publicAddresses.filter((address) => !address.includes(":")).sort()).toEqual(["1.1.1.1", "8.8.8.8"]);
  expect(sample.publicAddresses.filter((address) => address.includes(":"))).toHaveLength(1);
  expect(sample.privateAddresses.sort()).toEqual(["10.20.30.40", "10.20.30.50", "203.0.113.77", "fd00:cf::10"]);

  const scans = portScans(sample.packets, 20);
  expect(scans.map((scan) => scan.source)).toEqual([
    must(sample.publicAddresses.find((address) => address.includes(":"))),
    "203.0.113.77",
  ]);
  expect(scans.map((scan) => [scan.ports[0], scan.ports.at(-1), scan.ports.length])).toEqual([
    [2000, 2019, 20],
    [3000, 3019, 20],
  ]);

  expect(flagNames(0x1b)).toEqual(["FIN", "SYN", "PSH", "ACK"]);
  expect([790, 4714, 5948, 1.5 * 1024 * 1024].map(sizeText)).toEqual(["790 B", "4.60 KB", "5.81 KB", "1.50 MB"]);
  expect(istOfSeconds(1_749_637_800)).toBe("11-06-2025 04:00:00 PM IST");
  for (const address of ["10.20.30.40", "203.0.113.77", "198.51.100.7", "192.0.2.1", "127.0.0.1", "169.254.1.1"]) {
    expect(isPublic(address), address).toBe(false);
  }
  for (const address of ["fd00:cf::10", "fe80::1", "::1", "2001:db8::1", "172.16.0.1", "100.64.0.1", "224.0.0.1"]) {
    expect(isPublic(address), address).toBe(false);
  }
  for (const address of ["8.8.8.8", "1.1.1.1", "2100:3946:b9d8::e0f4"]) expect(isPublic(address), address).toBe(true);
});

// ---- Journey B: a capture file analysed offline --------------------------------------------------------

test("a capture file is analysed offline and the page reports what the file holds", async ({ page, request }) => {
  test.setTimeout(240_000);
  const sample = await sampleFacts();
  const file = await readFile(CAPTURE_PATH);
  const status = await fetchStatus(request);
  const rules = await fetchRules(request);
  const scanRule = must(rules.find((rule) => rule.rule_id === "NET-001"), "the port scan rule");
  const knownRule = must(rules.find((rule) => rule.rule_id === "NET-005"), "the known malicious rule");
  const scans = portScans(sample.packets, scanRule.threshold);
  const attacker = must(sample.publicAddresses.find((address) => address.includes(":")));
  const lookups = countRequests(page, LOOKUPS, "POST");
  const uploads = countRequests(page, /\/api\/v1\/network\/pcap$/, "POST");
  let id = "";

  await test.step("the idle page says what is kept and what is not", async () => {
    await openNetwork(page);
    await expect(page.getByText("Packet contents are never stored.")).toBeVisible();
    await expect(panel(page, "Live capture")).toContainText("Packet payloads are never stored.");
    await expect(uploadPanel(page)).toContainText("The server keeps the results, not the file.");
    await expect(uploadPanel(page)).toContainText(
      `Files ending in .pcap, .pcapng or .cap, up to ${status.analysis.max_upload_mb} MB.`,
    );
    await expect(panel(page, "External IP addresses")).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Analyse file" })).toBeDisabled();
  });

  await test.step("the file is chosen in the browser's own file chooser and analysed", async () => {
    const chooser = page.waitForEvent("filechooser");
    await page.getByLabel("Capture file", { exact: true }).click();
    await (await chooser).setFiles(CAPTURE_PATH);
    await expect(uploadPanel(page)).toContainText(`Selected: ${CAPTURE_NAME} (${sizeText(file.length)})`);
    await page.getByRole("button", { name: "Analyse file" }).click();

    await expect(page).toHaveURL(/\/network\?session=[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/);
    id = must(new URL(page.url()).searchParams.get("session"), "a session in the address");
    // The known malicious address is raised once its lookup is in, so the count may still be two.
    await expect(uploadPanel(page).getByRole("status")).toContainText(/Analysis complete: 72 packets, [23] alerts\./);
    await expect
      .poll(
        async () => {
          const detail = await fetchSession(request, id);
          return `${detail.status} ${detail.alerts_total} ${detail.enrichment.pending}`;
        },
        { message: "the analysis and the lookups are over", timeout: 30_000 },
      )
      .toBe("completed 3 0");
    await expect(historyRow(page, `Capture file ${CAPTURE_NAME}`)).toContainText("Completed");
  });

  const detail = await fetchSession(request, id);

  await test.step("the totals are the ones in the file", async () => {
    const summary = panel(page, "Session summary");
    await expect(fact(summary, "Packets")).toHaveText(String(sample.packets.length));
    await expect(fact(summary, "Data")).toHaveText(sizeText(sample.bytes));
    await expect(fact(summary, "Flows seen")).toHaveText(String(sample.flows.length));
    await expect(fact(summary, "Active flows")).toHaveText("0");
    await expect(fact(summary, "Alerts")).toHaveText("3");
    await expect(fact(summary, "Packets dropped")).toHaveText("0");
    await expect(fact(summary, "Source")).toHaveText(`Capture file: ${CAPTURE_NAME}`);
    await expect(fact(summary, "Capture started")).toContainText(istText(detail.started_at));
    await expect(fact(summary, "First packet")).toContainText(
      istOfSeconds(Math.min(...sample.packets.map((packet) => packet.seconds))),
    );
    await expect(fact(summary, "Last packet")).toContainText(
      istOfSeconds(Math.max(...sample.packets.map((packet) => packet.seconds))),
    );
    await expect(summary.getByRole("list", { name: "Alerts by rule" }).getByRole("listitem")).toHaveText([
      "NET-001: 2",
      "NET-005: 1",
    ]);
    const counters = summary.getByRole("region", { name: "What the totals leave out" });
    await expect(counters.locator("dt > span:first-child")).toHaveText([
      "Packets dropped by the monitor",
      "Non-IP packets",
      "Malformed packets",
      "Flows closed early",
      "Flows stored",
      "Flows not stored",
      "Repeat alerts suppressed",
      "Alerts lost",
      "Top talkers truncated",
    ]);
    await expect(counters.locator("dt > span:last-child")).toHaveText([
      "0",
      String(sample.nonIp),
      "0",
      "0",
      String(sample.flows.length),
      "0",
      "0",
      "0",
      "No",
    ]);

    const protocols = panel(page, "Protocol distribution").getByRole("list", { name: "Packets by protocol" });
    for (const protocol of ["tcp", "udp", "icmp"] as const) {
      const packets = sample.packets.filter((packet) => packet.protocol === protocol).length;
      const share = Math.round((packets / sample.packets.length) * 100);
      await expect(
        protocols.getByRole("group", { name: `${protocol.toUpperCase()}: ${packets} packets, ${share}%`, exact: true }),
      ).toBeVisible();
    }
    for (const [name, side] of [
      ["Top source IPs by bytes", "src"],
      ["Top destination IPs by bytes", "dst"],
    ] as const) {
      // Each row reads its rank, the address, the count for screen readers and the count in full figures.
      await expect(panel(page, "Top talkers").getByRole("list", { name, exact: true }).getByRole("listitem")).toHaveText(
        talkers(sample.packets, side).map(
          (talker, index) =>
            new RegExp(
              `^0${index + 1}${escapeRegExp(talker.address)}: ${talker.bytes} bytes${String(talker.bytes).replace(/\B(?=(\d{3})+$)/g, ",")}$`,
            ),
        ),
      );
    }
  });

  await test.step("the flows are listed with metadata only, as the file has them", async () => {
    const flows = panel(page, "Flows");
    await expect(flows.locator("thead th")).toHaveText([...FLOW_COLUMNS]);
    const stored = (await fetchFlows(request, id)).items;
    expect(stored, "flows the API lists").toHaveLength(sample.flows.length);
    for (const flow of stored) {
      expect(Object.keys(flow).sort(), "everything the API says about a flow").toEqual([...FLOW_FIELDS]);
      expect(flow.tcp_flag_names, "flag names follow the flag bits").toEqual(
        flow.tcp_flags === null ? [] : flagNames(flow.tcp_flags),
      );
    }
    expect(
      stored.map(factOf).map(inMilliseconds).sort(byConversation),
      "the API's flows against the packets in the file",
    ).toEqual(sample.flows.map(inMilliseconds).sort(byConversation));
    expect(
      stored.map((flow) => Date.parse(flow.first_seen)),
      "newest first",
    ).toEqual([...stored.map((flow) => Date.parse(flow.first_seen))].sort((later, earlier) => earlier - later));

    await expect(
      flows.getByRole("rowheader", { name: flowName(must(stored[0])), exact: true }),
      "the name a screen reader reads for the first flow",
    ).toBeVisible();
    const shown = await readFlowTable(page, sample.flows.length);
    expect(shown, "the table against the API, row for row").toEqual(stored.map(rowOf));
    const convo = must(stored.find((flow) => flow.tcp_flags === 0x1b), "the one connection that opened and closed");
    expect(rowOf(convo)[8], "a connection both sides closed").toBe("Closed");
    expect(stored.filter((flow) => flow.close_reason === "ended")).toHaveLength(sample.flows.length - 1);
  });

  await test.step("the port scans are alerts, with the evidence that supports them", async () => {
    expect(scans).toHaveLength(2);
    const window = must(scanRule.window_seconds, "a window for the port scan rule");
    for (const scan of scans) {
      const card = alertCard(page, "NET-001", scan.source);
      await expect(card).toContainText(/Medium\s*NET-001/);
      await expect(card.getByRole("heading", { level: 3 })).toHaveText("Port scan");
      await expect(card).toContainText(scanSentence(scan, scanRule.threshold, window));
      await expect(card).toContainText(
        `Observed ${scan.ports.length} ports against a threshold of ${scanRule.threshold} ports, within ${window} seconds.`,
      );
      await expect(fact(card, "Source")).toHaveText(scan.source);
      await expect(fact(card, "Destination")).toHaveText(must(scan.targets[0]));
      await expect(fact(card, "Protocol")).toHaveText("TCP");
      await expect(fact(card, "First observed")).toContainText(istOfSeconds(scan.first));
      await expect(fact(card, "Last observed")).toContainText(istOfSeconds(scan.last));

      const toggle = card.getByRole("button", { name: "Evidence for rule NET-001", exact: true });
      await expect(toggle).toHaveAttribute("aria-expanded", "false");
      await expect(fact(card, "Unique ports")).toHaveCount(0);
      await toggle.click();
      await expect(toggle).toHaveAttribute("aria-expanded", "true");
      await expect(fact(card, "Unique ports")).toHaveText(String(scan.ports.length));
      await expect(fact(card, "Sample ports")).toHaveText(scan.ports.join(", "));
      await expect(fact(card, "Unique targets")).toHaveText(String(scan.targets.length));
      await expect(fact(card, "Top targets › 1")).toHaveText(
        `Address: ${must(scan.targets[0])}, Count: ${scan.ports.length}`,
      );
      await expect(fact(card, "Truncated")).toHaveText("No");
    }
  });

  await test.step("the documentation-range scanner is not looked up, because it is not a public address", async () => {
    const card = alertCard(page, "NET-001", "203.0.113.77");
    await expect(card).toContainText("No public address");
    await expect(card).toContainText("The traffic involves no public address, so there is nothing to look up.");
    await expect(card.getByRole("button", { name: /Look up address/ })).toHaveCount(0);
  });

  await test.step("the public attacker was looked up, and the alert for it says what the providers said", async () => {
    const stored = must(
      (await fetchIndicators(request, { q: attacker, limit: 10 })).items.find((item) => item.indicator_value === attacker),
      "the indicator that the lookup stored",
    );
    const dossier = await fetchIndicator(request, stored.indicator_id);
    const answered = dossier.providers.filter((provider) => provider.status === "ok").map((provider) => provider.display_name);
    expect(stored.risk_score, "a known critical address").toBe(100);
    expect(stored.classification).toBe("critical");

    const alerts = (await fetchAlerts(request, id)).items;
    const known = must(alerts.find((alert) => alert.rule_id === "NET-005"), "the known malicious alert");
    const seen = externalFacts(sample.packets, attacker);
    const card = alertCard(page, "NET-005", attacker);
    await expect(card).toContainText(/Critical\s*NET-005/);
    await expect(card.getByRole("heading", { level: 3 })).toHaveText("Communication with a known malicious address");
    await expect(card).toContainText(
      `Monitored hosts received traffic from ${attacker}, which has a CipherForge risk score of ${stored.risk_score}/100 ` +
        `(${stored.classification}), at or above the configured minimum of ${knownRule.threshold}. ` +
        `Providers that returned data: ${answered.join(", ")}. ` +
        `Traffic seen between ${istOfSeconds(seen.first)} and ${istOfSeconds(seen.last)}.`,
    );
    await expect(card).toContainText(
      `Observed ${stored.risk_score} risk score against a threshold of ${knownRule.threshold} risk score.`,
    );
    await expect(fact(card, "Source")).toHaveText(attacker);
    await expect(fact(card, "Destination")).toHaveText(must(known.dst_ip));
    expect(answered, "providers that returned data").toEqual(["AbuseIPDB", "AlienVault OTX", "VirusTotal", "ThreatFox"]);
    await expect(card.getByRole("list", { name: "Provider answers" }).getByRole("listitem")).toHaveText(
      providerLines(dossier.providers),
    );
    await expect(card).toContainText(
      new RegExp(`Risk score\\s*100 of 100\\s*Classification\\W*${CLASSIFICATION_LABELS.critical}`),
    );
    expect(providerLines(dossier.providers).slice(2)).toEqual([
      "VirusTotal: Answered, verdict malicious",
      "ThreatFox: Answered, verdict malicious",
    ]);

    const toggle = card.getByRole("button", { name: "Evidence for rule NET-005", exact: true });
    await toggle.click();
    await expect(toggle).toHaveAttribute("aria-expanded", "true");
    await expect(fact(card, "Address")).toHaveText(attacker);
    await expect(fact(card, "Risk score")).toHaveText(String(stored.risk_score));
    await expect(fact(card, "Packets")).toHaveText(String(seen.packets));
    await expect(fact(card, "Bytes")).toHaveText(sizeText(seen.bytes));
  });

  await test.step("every public address is listed once, with its traffic and what its lookup said", async () => {
    const external = panel(page, "External IP addresses");
    await expect(fact(external, "Public addresses")).toHaveText(String(sample.publicAddresses.length));
    await expect(fact(external, "Looked up")).toHaveText(String(sample.publicAddresses.length));
    for (const term of ["Pending", "Failed", "Unavailable", "Skipped or not looked up"]) {
      await expect(fact(external, term)).toHaveText("0");
    }

    const alerted = new Set(scans.map((scan) => scan.source));
    const order = [...sample.publicAddresses].sort(
      (first, second) =>
        Number(alerted.has(second)) - Number(alerted.has(first)) ||
        externalFacts(sample.packets, second).packets - externalFacts(sample.packets, first).packets,
    );
    await expect(
      external.getByRole("list", { name: "External IP addresses", exact: true }).getByRole("heading", { level: 3 }),
    ).toHaveText(order);

    for (const address of order) {
      const seen = externalFacts(sample.packets, address);
      const card = externalCard(page, address);
      await expect(fact(card, "First seen")).toContainText(istOfSeconds(seen.first));
      await expect(fact(card, "Last seen")).toContainText(istOfSeconds(seen.last));
      await expect(fact(card, "Packets")).toHaveText(String(seen.packets));
      await expect(fact(card, "Data")).toHaveText(sizeText(seen.bytes));
      await expect(fact(card, "Traffic sent to it")).toHaveText(seen.sentTo ? "Yes" : "No");
      await expect(fact(card, "Raised an alert")).toHaveText(alerted.has(address) ? "Yes" : "No");
      for (const [term, name, values] of [
        ["Ports", "Ports seen with", seen.ports.map(String)],
        ["Protocols", "Protocols seen with", seen.protocols],
        ["Peers", "Peers of", seen.peers],
      ] as const) {
        if (values.length === 0) {
          await expect(fact(card, term)).toHaveCount(0);
          continue;
        }
        await expect(fact(card, term).getByRole("list", { name: `${name} ${address}` }).getByRole("listitem")).toHaveText([
          ...values,
        ]);
      }

      const stored = must(
        (await fetchIndicators(request, { q: address, limit: 10 })).items.find((item) => item.indicator_value === address),
        `the indicator that the lookup stored for ${address}`,
      );
      const dossier = await fetchIndicator(request, stored.indicator_id);
      const lookup = must(detail.external_ips.find((entry) => entry.address === address)).enrichment;
      expect([lookup.status, lookup.indicator_id, lookup.risk_score]).toEqual([
        "completed",
        stored.indicator_id,
        stored.risk_score,
      ]);
      expect(providerLines(lookup.providers), "the session's record of the answers against the stored dossier").toEqual(
        providerLines(dossier.providers),
      );
      await expect(card.getByRole("list", { name: "Provider answers" }).getByRole("listitem")).toHaveText(
        providerLines(dossier.providers),
      );
      await expect(card).toContainText(
        new RegExp(
          `Looked up\\s*Risk score\\s*${stored.risk_score} of 100\\s*Classification\\W*${CLASSIFICATION_LABELS[stored.classification]}`,
        ),
      );
    }
  });

  await test.step("no private, loopback or documentation address was looked up", async () => {
    expect(detail.external_ips.map((entry) => entry.address).sort(), "addresses the session offers for lookup").toEqual(
      [...sample.publicAddresses].sort(),
    );
    for (const address of sample.privateAddresses) {
      expect(await indicatorIdOf(request, address), `an indicator for ${address}`).toBeUndefined();
    }
    for (const prefix of NEVER_LOOKED_UP) {
      const found = await fetchIndicators(request, { q: prefix, limit: 100 });
      expect(
        found.items.map((item) => item.indicator_value).filter((value) => value.startsWith(prefix)),
        `indicators that start with ${prefix}`,
      ).toEqual([]);
    }
  });

  expect(lookups.count, "lookups the browser itself asked for").toBe(0);
  expect(uploads.count, "uploads the browser made").toBe(1);
  expect(await auditOfSession(id)).toContainEqual({ action: "NETWORK_PCAP_ANALYZE", result: "success" });
});

// ---- Narrowing the alerts ---------------------------------------------------------------------------------------

test("the alerts can be narrowed by severity and by rule, and widened again", async ({ page, request }) => {
  const session = await analyseSample(request);
  await openSession(page, session.id);
  const alerts = panel(page, "Alerts");
  const cards = alerts.getByRole("list", { name: "Alerts", exact: true }).locator(":scope > li");
  const severity = alerts.getByRole("group", { name: "Severity" });
  const critical = severity.getByRole("button", { name: "Critical", exact: true });
  const rule = alerts.getByLabel("Rule", { exact: true });
  const none = alerts.getByText("No alerts match these filters.");
  await expect(cards).toHaveCount(3);

  await critical.click();
  await expect(critical).toHaveAttribute("aria-pressed", "true");
  await expect(cards).toHaveCount(1);
  await expect(cards.first()).toContainText("NET-005");

  await rule.selectOption("NET-001");
  await expect(none).toBeVisible();
  await expect(cards).toHaveCount(0);

  await alerts.getByRole("button", { name: "Clear filters" }).click();
  await expect(critical).toHaveAttribute("aria-pressed", "false");
  await expect(cards).toHaveCount(3);

  await rule.selectOption("NET-001");
  await expect(cards).toHaveCount(2);
  for (const card of await cards.all()) await expect(card).toContainText(/Medium\s*NET-001/);
  await severity.getByRole("button", { name: "High", exact: true }).click();
  await expect(none).toBeVisible();
});

// ---- Traffic that must never be looked up, and what packets carry --------------------------------------------------

const START = 1_749_637_800;
const EMPTY = Buffer.alloc(0);
const LOOKUPS = /\/api\/v1\/(intel\/investigate|network\/alerts\/[^/]+\/enrich)/;

/** Private, loopback, link-local and documentation addresses only: nothing a provider may be asked about. */
const NON_PUBLIC: readonly Segment[] = [
  { src: "10.1.1.5", dst: "192.168.1.9", srcPort: 51000, dstPort: 443, flags: 0x02, payload: EMPTY },
  { src: "127.0.0.1", dst: "127.0.0.1", srcPort: 51001, dstPort: 8000, flags: 0x02, payload: EMPTY },
  { src: "169.254.10.2", dst: "10.1.1.5", srcPort: 51002, dstPort: 80, flags: 0x02, payload: EMPTY },
  { src: "203.0.113.10", dst: "10.1.1.5", srcPort: 51003, dstPort: 22, flags: 0x02, payload: EMPTY },
  { src: "198.51.100.7", dst: "192.0.2.1", srcPort: 51004, dstPort: 25, flags: 0x02, payload: EMPTY },
  { src: "172.16.4.4", dst: "192.168.1.9", srcPort: 51005, dstPort: 53, flags: 0x02, payload: EMPTY },
];

/** Chooses a file that exists only in memory and sends it, as a person does after picking one from disk. */
async function analyseInPage(page: Page, name: string, data: Buffer): Promise<void> {
  await page
    .getByLabel("Capture file", { exact: true })
    .setInputFiles({ name, mimeType: "application/octet-stream", buffer: data });
  await page.getByRole("button", { name: "Analyse file" }).click();
}

/** The session the address names, once the page has put one there. */
async function sessionInAddress(page: Page): Promise<string> {
  await expect(page).toHaveURL(/[?&]session=[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}/);
  return must(new URL(page.url()).searchParams.get("session"), "a session in the address");
}

/** The text of every answer the page gets from the monitoring API from now on. */
function recordBodies(page: Page): { texts: () => Promise<string[]> } {
  const reading: Promise<string>[] = [];
  page.on("response", (response) => {
    if (/\/api\/v1\/network\//.test(response.url())) reading.push(response.text().catch(() => ""));
  });
  return { texts: () => Promise.all(reading) };
}

test("traffic between private, loopback and documentation addresses is analysed but never looked up", async ({
  page,
  request,
}) => {
  test.setTimeout(120_000);
  const lookups = countRequests(page, LOOKUPS, "POST");
  const before = (await fetchOverview(request)).kpis.lookups_24h;
  await openNetwork(page);
  await analyseInPage(page, `private-only-${uniqueTag()}.pcap`, buildCapture(NON_PUBLIC, START));
  const id = await sessionInAddress(page);
  await expect(uploadPanel(page).getByRole("status")).toContainText(
    `Analysis complete: ${NON_PUBLIC.length} packets, 0 alerts.`,
  );

  const summary = panel(page, "Session summary");
  await expect(fact(summary, "Packets")).toHaveText(String(NON_PUBLIC.length));
  await expect(fact(summary, "Alerts")).toHaveText("0");
  const external = panel(page, "External IP addresses");
  await expect(external).toContainText("No public addresses were seen in this session's traffic.");
  await expect(fact(external, "Public addresses")).toHaveText("0");
  await expect(fact(external, "Looked up")).toHaveText("0");
  await expect(panel(page, "Alerts")).toContainText("No alerts were raised in this session.");
  await expect(panel(page, "Alerts")).toContainText("it is not a statement that the traffic is safe");
  await expect(
    panel(page, "Flows").getByRole("rowheader", { name: "127.0.0.1:51001 to 127.0.0.1:8000", exact: true }),
    "the person's own traffic is listed with its addresses",
  ).toBeVisible();

  const detail = await fetchSession(request, id);
  expect(detail.external_ips, "addresses offered for a lookup").toEqual([]);
  expect(detail.enrichment.total, "lookups the session asked for").toBe(0);
  for (const address of new Set(NON_PUBLIC.flatMap((segment) => [segment.src, segment.dst]))) {
    expect(await indicatorIdOf(request, address), `an indicator for ${address}`).toBeUndefined();
  }
  expect(lookups.count, "lookups the browser itself asked for").toBe(0);
  expect((await fetchOverview(request)).kpis.lookups_24h, "lookups in the last 24 hours").toBe(before);
});

test("what packets carry is counted but never stored, sent back or shown", async ({ page, request }) => {
  test.setTimeout(120_000);
  const tag = uniqueTag();
  const name = `payload-check-${tag}.pcap`;
  const marker = `PAYLOAD-${tag}-MUST-NOT-BE-KEPT`;
  const payload = Buffer.from(marker.repeat(3));
  const frame = 54 + payload.length;
  const segments: Segment[] = [
    { src: "10.9.9.1", dst: "10.9.9.2", srcPort: 52000, dstPort: 5555, flags: 0x18, payload },
    { src: "10.9.9.2", dst: "10.9.9.1", srcPort: 5555, dstPort: 52000, flags: 0x18, payload },
  ];
  const answers = recordBodies(page);
  const before = (await fetchOverview(request)).kpis.lookups_24h;

  await openNetwork(page);
  await analyseInPage(page, name, buildCapture(segments, START));
  const id = await sessionInAddress(page);
  await expect(uploadPanel(page).getByRole("status")).toContainText("Analysis complete: 2 packets, 0 alerts.");
  await expect(fact(panel(page, "Session summary"), "Data")).toHaveText(sizeText(2 * frame));
  const flows = panel(page, "Flows");
  await expect(flows.getByRole("rowheader", { name: "10.9.9.1:52000 to 10.9.9.2:5555", exact: true })).toBeVisible();
  expect(await flowCells(flows), "the flow, with its counts and flags and nothing it carried").toEqual([
    [
      "10.9.9.1:52000 → 10.9.9.2:5555",
      "TCP",
      istOfSeconds(START),
      istOfSeconds(START),
      "0.1 s",
      "1 / 1",
      `${sizeText(frame)} / ${sizeText(frame)}`,
      "PSH ACK",
      "Session ended",
    ],
  ]);

  const needles = [marker, Buffer.from(marker).toString("hex"), Buffer.from(marker).toString("base64")];
  const storage = await page.evaluate(() => JSON.stringify({ local: { ...localStorage }, session: { ...sessionStorage } }));
  const database = await demoDatabaseBytes();
  expect(
    database.some((file) => file.includes(name)),
    "the database holds the name of the file, so that a search of it can find what it was given",
  ).toBe(true);
  const places: [string, string | Buffer][] = [
    ["the page", await page.content()],
    ["the words on the page", await page.locator("body").innerText()],
    ["the browser's storage", storage],
    ["what the API says of the session", JSON.stringify(await fetchSession(request, id))],
    ["what the API says of its flows", JSON.stringify(await fetchFlows(request, id))],
    ["what the API says of its alerts", JSON.stringify(await fetchAlerts(request, id))],
    ...(await answers.texts()).map((text, index): [string, string] => [`answer ${index + 1} to the page`, text]),
    ...database.map((file, index): [string, Buffer] => [`database file ${index + 1}`, file]),
  ];
  for (const [where, content] of places) {
    for (const needle of needles) expect(content.includes(needle), `${where} holds the payload`).toBe(false);
  }
  expect((await fetchOverview(request)).kpis.lookups_24h, "lookups in the last 24 hours").toBe(before);
});

// ---- Files the page refuses ---------------------------------------------------------------------------------------

const REFUSED = [
  {
    why: "a file that is not a capture",
    name: "notes.txt",
    size: 64,
    message: '"notes.txt" is not a capture file. Choose a file that ends in .pcap, .pcapng or .cap.',
  },
  {
    why: "a name with nothing before the extension",
    name: ".pcap",
    size: 64,
    message: 'The file has no name before ".pcap". Rename it and choose it again.',
  },
  {
    why: "a name too long to send",
    name: `${"long-name-".repeat(110)}.pcap`,
    size: 64,
    message: "The file name is too long. Rename the file and choose it again.",
  },
  {
    why: "an empty file",
    name: "empty.pcap",
    size: 0,
    message: '"empty.pcap" is empty, so there is nothing to analyse.',
  },
  {
    why: "a file over the limit the page was told",
    name: "big.pcap",
    size: 1.5 * 1024 * 1024,
    message: '"big.pcap" is 1.50 MB, over the 1 MB limit.',
  },
] as const;

test("a file the page can tell is wrong is refused with the reason, and nothing is sent", async ({ page, request }) => {
  test.setTimeout(120_000);
  // The server's limit is 50 MB, more than the browser tool can hold in memory: the page is told 1 MB instead.
  await page.route("**/api/v1/network/status", async (route) => {
    const response = await route.fetch();
    if (!response.ok()) return route.fulfill({ response });
    const status = (await response.json()) as NetworkStatus;
    return route.fulfill({
      status: response.status(),
      json: { ...status, analysis: { ...status.analysis, max_upload_mb: 1 } },
    });
  });
  const uploads = countRequests(page, /\/api\/v1\/network\/pcap$/, "POST");
  const before = (await fetchSessions(request)).total;

  await openNetwork(page);
  await expect(uploadPanel(page)).toContainText("up to 1 MB.");
  const refusal = page.getByRole("alert").filter({ hasText: "The file was not sent" });
  for (const file of REFUSED) {
    await test.step(`refuses ${file.why}`, async () => {
      await page
        .getByLabel("Capture file", { exact: true })
        .setInputFiles({ name: file.name, mimeType: "application/octet-stream", buffer: Buffer.alloc(file.size) });
      await expect(uploadPanel(page)).toContainText(`Selected: ${file.name} (${sizeText(file.size)})`);
      await page.getByRole("button", { name: "Analyse file" }).click();
      await expect(refusal).toContainText(file.message);
      await page.getByRole("button", { name: "Dismiss" }).click();
      await expect(refusal).toHaveCount(0);
    });
  }
  expect(uploads.count, "uploads the browser made").toBe(0);
  expect((await fetchSessions(request)).total, "sessions that exist").toBe(before);
});

test("a file that is not a readable capture is refused by the server, and nothing of it is kept", async ({
  page,
  request,
  guard,
}) => {
  guard.expectStatus(422);
  const garbage = Buffer.from("This is not a capture file. ".repeat(20));
  const before = (await fetchSessions(request)).total;
  expect(await refusalOf(await postCapture(request, "garbage.pcap", garbage))).toMatchObject({
    status: 422,
    code: "invalid_capture_file",
  });

  await openNetwork(page);
  await analyseInPage(page, "garbage.pcap", garbage);
  const notice = page.getByRole("alert").filter({ hasText: "Not a readable capture file" });
  await expect(notice).toContainText(
    "That file is not a readable PCAP or PCAPNG capture, or it holds no complete packet. Nothing was kept from it.",
  );
  await expect(notice).toContainText(/Reference: \S+/);
  expect((await fetchSessions(request)).total, "sessions that exist").toBe(before);
});

// ---- The history of sessions --------------------------------------------------------------------------------------

test("the history lists each session, opens one on request and deletes one only after asking", async ({
  page,
  request,
}) => {
  test.setTimeout(120_000);
  const tag = uniqueTag();
  const firstName = `history-first-${tag}.pcap`;
  const secondName = `history-second-${tag}.pcap`;
  const first = await analyseViaApi(request, firstName, buildCapture(NON_PUBLIC, START));
  const second = await analyseViaApi(request, secondName, buildCapture(NON_PUBLIC.slice(0, 2), START));
  const history = panel(page, "Session history");
  const dialog = page.getByRole("dialog", { name: "Delete this session?" });

  await test.step("lists the sessions, newest first", async () => {
    await openNetwork(page);
    await expect(history.getByRole("rowheader")).toHaveText(
      [`Capture file ${secondName}`, `Capture file ${firstName}`],
      { useInnerText: true },
    );
    for (const [name, session, packets] of [
      [firstName, first, NON_PUBLIC.length],
      [secondName, second, 2],
    ] as const) {
      const row = historyRow(page, `Capture file ${name}`);
      await expect(row.getByRole("cell").nth(0)).toContainText("Completed");
      await expect(row.getByRole("cell").nth(1)).toContainText(istText(session.started_at));
      await expect(row.getByRole("cell").nth(3)).toHaveText(String(packets));
      await expect(row.getByRole("cell").nth(4)).toHaveText("0");
    }
    await expect(panel(page, "Session")).toContainText("No session is open yet.");
  });

  await test.step("opens a session and goes back to none", async () => {
    await history.getByRole("button", { name: `View session ${firstName}`, exact: true }).click();
    await expect(page).toHaveURL(new RegExp(`[?&]session=${first.id}$`));
    await expect(fact(panel(page, "Session summary"), "Source")).toHaveText(`Capture file: ${firstName}`);
    await expect(history.getByRole("button", { name: `Viewing session ${firstName}`, exact: true })).toBeVisible();
    await expect(page.getByText("You are looking at a session you picked.")).toBeVisible();
    await page.getByRole("button", { name: "Clear selection" }).click();
    await expect(page).not.toHaveURL(/session=/);
    await expect(panel(page, "Session")).toContainText("No session is open yet.");
  });

  await test.step("asks before it deletes, and keeps the session when told not to", async () => {
    await history.getByRole("button", { name: `View session ${secondName}`, exact: true }).click();
    await expect(fact(panel(page, "Session summary"), "Source")).toHaveText(`Capture file: ${secondName}`);
    await history.getByRole("button", { name: `Delete session ${secondName}`, exact: true }).click();
    await expect(dialog).toBeVisible();
    await expect(fact(dialog, "Capture file:")).toHaveText(secondName);
    await expect(fact(dialog, "Started:")).toHaveText(istText(second.started_at));
    await expect(fact(dialog, "Contains:")).toHaveText("2 packets, 2 flows, 0 alerts");
    await expect(dialog).toContainText(
      "This permanently removes the session with its stored flows, its alerts and the address lookup results kept with it. It cannot be undone.",
    );
    await expect(dialog).toContainText("The audit log is kept as it is, and gains a record that this session was deleted.");
    await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
    await expect(dialog).toBeHidden();
    await expect(historyRow(page, `Capture file ${secondName}`)).toHaveCount(1);
    expect(await statusOf(request, `/api/v1/network/sessions/${second.id}`), "a session that was kept").toBe(200);
  });

  await test.step("deletes the session when told to, and the page no longer shows it", async () => {
    await history.getByRole("button", { name: `Delete session ${secondName}`, exact: true }).click();
    await dialog.getByRole("button", { name: "Delete session", exact: true }).click();
    await expect(dialog).toBeHidden();
    await expect(historyRow(page, `Capture file ${secondName}`)).toHaveCount(0);
    await expect(historyRow(page, `Capture file ${firstName}`)).toHaveCount(1);
    await expect(page).not.toHaveURL(/session=/);
    await expect(panel(page, "Session")).toContainText("No session is open yet.");
    expect(await statusOf(request, `/api/v1/network/sessions/${second.id}`), "a session that was deleted").toBe(404);
    expect(await statusOf(request, `/api/v1/network/sessions/${first.id}`), "the other session").toBe(200);
    expect(await auditOfSession(second.id)).toEqual(
      expect.arrayContaining([
        { action: "NETWORK_PCAP_ANALYZE", result: "success" },
        { action: "NETWORK_SESSION_DELETE", result: "success" },
      ]),
    );
  });
});

test("a link to a session that does not exist, or to something that is not a session, is met calmly", async ({
  page,
  guard,
}) => {
  guard.expectStatus(404);
  const reads = countRequests(page, /\/api\/v1\/network\/sessions\/[^/?]/);

  await openNetwork(page, `?session=${encodeURIComponent(TRAVERSAL_ID)}`);
  await expect(page.getByText("That session link was not understood")).toBeVisible();
  await expect(page.getByText("No session is open yet.")).toBeVisible();
  expect(reads.count, "requests for a session named by an address that is not an id").toBe(0);

  await openNetwork(page, "?session=00000000-0000-4000-8000-000000000000");
  const notice = page.getByRole("alert").filter({ hasText: "Session not found" });
  await expect(notice).toContainText("That session no longer exists, or it belongs to another account.");
  await panel(page, "Session").getByRole("button", { name: "Clear selection" }).click();
  await expect(page).not.toHaveURL(/session=/);
  await expect(page.getByText("No session is open yet.")).toBeVisible();
});

// ---- Journey C: live monitoring ---------------------------------------------------------------------------------

/** What the page calls the state of a session, written out here and not read from the app. */
const SESSION_STATE: Readonly<Record<string, string>> = {
  starting: "Starting",
  running: "Running",
  stopping: "Stopping",
  stopped: "Stopped",
  completed: "Completed",
  failed: "Failed",
  permission_denied: "Permission denied",
};

const LIFECYCLE = ["NETWORK_CAPTURE_START", "NETWORK_CAPTURE_STOP", "NETWORK_SESSION_DELETE"];

function liveCapture(page: Page): Locator {
  return panel(page, "Live capture");
}

/** The badge that names the state of the capture: a symbol, then the word. */
function stateBadge(live: Locator, word: "Ready" | "Running" | "Stopped"): Locator {
  return live.getByText(new RegExp(`^\\S?${word}$`));
}

/** "1 flow", "2 flows". */
function counted(count: number, word: string): string {
  return `${count} ${word}${count === 1 ? "" : "s"}`;
}

/** The number a page shows for a count, with or without thousands separators. */
async function figure(term: Locator): Promise<number> {
  return Number((await term.innerText()).replace(/\D/g, ""));
}

function conversation(flow: FlowFact): string {
  return JSON.stringify([flow.protocol, flow.src, flow.srcPort, flow.dst, flow.dstPort]);
}

/** What a flow is, without when it happened: the simulated feed is stamped with the moment it arrives. */
function shapeOf(flow: FlowFact) {
  return {
    protocol: flow.protocol,
    src: flow.src,
    srcPort: flow.srcPort,
    dst: flow.dst,
    dstPort: flow.dstPort,
    packetsOut: flow.packetsOut,
    packetsIn: flow.packetsIn,
    bytesOut: flow.bytesOut,
    bytesIn: flow.bytesIn,
    flags: flow.flags,
  };
}

test.describe("Journey C: live monitoring", () => {
  // The demo server swaps the packet source for a SIMULATED one: "Simulated office LAN" and "Simulated quiet link"
  // play made-up traffic (backend/devtools/synthetic_network.py), nothing is captured from this machine and no
  // privilege is needed. These tests therefore do NOT perform a real capture. A real, non-elevated live capture on a
  // real Npcap interface was verified by hand through the API, outside Playwright. The "busy" flag (someone else's
  // capture holds the single slot) cannot be shown either: the demo has one user.

  test("the page offers the interfaces the API reports, and choosing one starts nothing", async ({ page, request }) => {
    const listed = await fetchInterfaces(request);
    expect(listed.backend, "the capture backend").toMatchObject({ name: "simulated", available: true });
    expect(listed.interfaces.map(({ id, name }) => [id, name])).toEqual([
      ["simulated-lan", "Simulated office LAN"],
      ["simulated-quiet", "Simulated quiet link"],
    ]);
    expect(await fetchStatus(request)).toMatchObject({ state: "ready", interface: null, session_id: null, busy: false });
    const sessions = (await fetchSessions(request)).total;
    const starts = countRequests(page, /\/api\/v1\/network\/capture\/start$/, "POST");
    const listReads = countRequests(page, /\/api\/v1\/network\/interfaces(\?refresh=true)?$/, "GET");

    await openNetwork(page);
    const live = liveCapture(page);
    const choice = live.getByLabel("Interface", { exact: true });
    await expect(stateBadge(live, "Ready")).toBeVisible();
    await expect(live.getByText("Ready. Choose an interface and press Start.")).toBeVisible();
    await expect(choice.getByRole("option")).toHaveText(
      listed.interfaces.map((entry) => `${entry.name} - ${entry.description}`),
    );
    await expect(fact(live, "Capture backend")).toHaveText(/^simulated\s*\S?Available$/);
    await expect(live.getByText("Capture interface", { exact: true }), "no interface before a capture").toHaveCount(0);
    const stop = live.getByRole("button", { name: "Stop capture" });
    await expect(stop).toHaveAttribute("aria-disabled", "true");
    await expect(stop).toHaveAccessibleDescription("No capture of yours is running.");
    await expect(live.getByRole("button", { name: "Start capture" })).not.toHaveAttribute("aria-disabled", "true");

    for (const entry of listed.interfaces) {
      await choice.selectOption(entry.id);
      await expect(live.getByText(`Addresses: ${entry.addresses.join(", ")}`)).toBeVisible();
    }

    const reads = listReads.count;
    await live.getByRole("button", { name: "Refresh interfaces" }).click();
    await expect.poll(() => listReads.count, { message: "the list is asked for once more" }).toBe(reads + 1);
    await expect(choice.getByRole("option")).toHaveCount(listed.interfaces.length);

    expect(starts.count, "start requests made by choosing an interface").toBe(0);
    expect(await fetchStatus(request)).toMatchObject({ state: "ready", session_id: null });
    expect((await fetchSessions(request)).total, "sessions after choosing").toBe(sessions);
  });

  test("a live capture is started and stopped from the page, and nothing keeps capturing afterwards", async ({
    page,
    request,
  }) => {
    test.setTimeout(240_000);
    const sample = await sampleFacts();
    const { interfaces } = await fetchInterfaces(request);
    const lan = must(interfaces.find((entry) => entry.id === "simulated-lan"), "the office LAN");
    const quiet = must(interfaces.find((entry) => entry.id === "simulated-quiet"), "the quiet link");
    const scanRule = must((await fetchRules(request)).find((rule) => rule.rule_id === "NET-001"), "the port scan rule");
    const scans = portScans(sample.packets, scanRule.threshold);
    const attacker = must(sample.publicAddresses.find((address) => address.includes(":")), "the public IPv6 address");
    const live = liveCapture(page);
    const summary = panel(page, "Session summary");
    const history = panel(page, "Session history");
    const dialog = page.getByRole("dialog", { name: "Delete this session?" });
    const starts = countRequests(page, /\/api\/v1\/network\/capture\/start$/, "POST");
    const stops = countRequests(page, /\/api\/v1\/network\/capture\/stop$/, "POST");
    const lookups = countRequests(page, LOOKUPS, "POST");
    let first = "";
    let second = "";
    let finished: SessionDetail | undefined;

    await test.step("a capture is started on the office LAN from the page", async () => {
      await openNetwork(page);
      await live.getByRole("button", { name: "Start capture" }).click();
      await expect(stateBadge(live, "Running")).toBeVisible();
      expect(starts.count, "start requests the page made").toBe(1);
      const start = live.getByRole("button", { name: "Start capture" });
      await expect(live.getByLabel("Interface", { exact: true })).toBeDisabled();
      await expect(start).toHaveAttribute("aria-disabled", "true");
      await expect(start).toHaveAccessibleDescription("A capture is already running. Stop it to start another.");
      await expect(live.getByRole("button", { name: "Stop capture" })).not.toHaveAttribute("aria-disabled", "true");
      await expect(live.getByText(`Capturing on ${lan.name}. The figures below update as packets arrive.`)).toBeVisible();
      await expect(fact(live, "Capture interface")).toHaveText(lan.name);

      // Someone else's capture is the only thing that makes the API say "busy", so a capture of one's own never does.
      const status = await settledStatus(request);
      expect(status, "the API's account of the capture").toMatchObject({
        state: "running",
        interface: lan.name,
        busy: false,
      });
      first = must(status.session_id, "a session for the running capture");
      expect(await fetchSession(request, first)).toMatchObject({
        source_kind: "live",
        interface: lan.name,
        status: "running",
        ended_at: null,
      });
      await expect(fact(summary, "Source")).toHaveText(`Live capture: ${lan.name}`);
      await expect(fact(summary, "Capture ended")).toHaveText("Still running");
      await expect(historyRow(page, `Live capture ${lan.name}`)).toContainText("Running");
      await expect(history.getByRole("button", { name: `Delete session ${lan.name}`, exact: true })).toBeDisabled();
      await expect(summary.getByRole("button", { name: "Delete session", exact: true })).toBeDisabled();
      await expect(history.getByText("A session cannot be deleted while it is running.")).toBeVisible();
    });

    await test.step("a second start is refused while the first runs, on either interface, and starts nothing", async () => {
      const before = (await fetchSessions(request)).total;
      for (const entry of interfaces) {
        expect(await refusalOf(await startCapture(request, entry.id)), `a start on ${entry.name}`).toMatchObject({
          status: 409,
          code: "capture_already_running",
        });
      }
      expect(
        await refusalOf(await request.delete(`/api/v1/network/sessions/${first}`)),
        "deleting the session that is still being filled",
      ).toMatchObject({ status: 409, code: "session_running" });
      expect((await fetchSessions(request)).total, "sessions after the refusals").toBe(before);
      expect(await fetchStatus(request)).toMatchObject({ state: "running", session_id: first, busy: false });
    });

    await test.step("the figures grow as the simulated traffic arrives, and the rules fire on it", async () => {
      const packets = (): Promise<number> => figure(fact(summary, "Packets"));
      await expect(fact(summary, "Packets")).toBeVisible();
      await expect.poll(packets, { message: "the first packets", timeout: 30_000 }).toBeGreaterThan(0);
      const early = await packets();
      await expect.poll(packets, { message: "more packets than before", timeout: 30_000 }).toBeGreaterThan(early);
      await expect
        .poll(packets, { message: "the whole scenario has arrived", timeout: 60_000 })
        .toBeGreaterThanOrEqual(sample.packets.length);
      await expect
        .poll(() => figure(fact(summary, "Flows seen")), { message: "every conversation is a flow", timeout: 30_000 })
        .toBeGreaterThanOrEqual(sample.flows.length);
      await expect.poll(() => figure(fact(summary, "Active flows")), { message: "flows still open" }).toBeGreaterThan(0);

      await expect
        .poll(async () => (await fetchAlerts(request, first)).items.map((alert) => alert.rule_id).sort(), {
          message: "the alerts the rules raise on the scenario",
          timeout: 60_000,
        })
        .toEqual(["NET-001", "NET-001", "NET-005"]);
      for (const scan of scans) await expect(alertCard(page, "NET-001", scan.source)).toBeVisible();
      await expect(alertCard(page, "NET-005", attacker)).toBeVisible();

      await expect
        .poll(async () => {
          const { enrichment } = await fetchSession(request, first);
          return `${enrichment.pending} pending of ${enrichment.total}`;
        }, { message: "the lookups are over", timeout: 60_000 })
        .toBe(`0 pending of ${sample.publicAddresses.length}`);
      await expect(fact(panel(page, "External IP addresses"), "Public addresses")).toHaveText(
        String(sample.publicAddresses.length),
      );
      for (const address of sample.publicAddresses) await expect(externalCard(page, address)).toBeVisible();
      for (const address of sample.privateAddresses) {
        await expect(externalCard(page, address), `${address} is not looked up`).toHaveCount(0);
        expect(await indicatorIdOf(request, address), `an indicator for ${address}`).toBeUndefined();
      }
      expect(lookups.count, "lookups the browser itself asked for").toBe(0);
    });

    await test.step("the capture is stopped from the page", async () => {
      await live.getByRole("button", { name: "Stop capture" }).click();
      await expect(stateBadge(live, "Stopped")).toBeVisible();
      expect(stops.count, "stop requests the page made").toBe(1);
      await expect(live.getByText("The capture is stopped.")).toBeVisible();
      await expect(live.getByRole("note").filter({ hasText: "Capture stopped" })).toContainText(
        "The capture ended. Its results are kept below, and you can start a new capture.",
      );
      await expect(live.getByLabel("Interface", { exact: true })).toBeEnabled();
      await expect(live.getByRole("button", { name: "Stop capture" })).toHaveAttribute("aria-disabled", "true");
      expect(await fetchStatus(request), "the API after the stop").toMatchObject({
        state: "stopped",
        busy: false,
        session_id: first,
      });

      finished = await fetchSession(request, first);
      expect(finished.status, "how the finished session is recorded").toMatch(/^(stopped|completed)$/);
      expect(finished.ended_at, "an end for the finished session").not.toBeNull();
      await expect(historyRow(page, `Live capture ${lan.name}`)).toContainText(
        SESSION_STATE[finished.status] ?? finished.status,
      );
      await expect(fact(summary, "Capture ended")).toContainText(istText(must(finished.ended_at)));
      await expect(fact(summary, "Packets")).toHaveText(String(finished.packets_total));
      await expect(fact(summary, "Flows seen")).toHaveText(String(finished.flows_total));
      await expect(fact(summary, "Active flows")).toHaveText("0");
      await expect(fact(summary, "Alerts")).toHaveText("3");
    });

    await test.step("the flows listed are the ones in the traffic that was fed to the capture", async () => {
      const done = must(finished, "the finished session");
      const stored = (await fetchFlows(request, first)).items;
      expect(stored, "flows the API lists").toHaveLength(done.flows_stored);
      expect(done.flows_total, "flows seen").toBeGreaterThanOrEqual(sample.flows.length);
      expect(new Set(sample.flows.map(conversation)).size, "conversations in the traffic").toBe(sample.flows.length);

      const seen = new Map(stored.map(factOf).map((flow) => [conversation(flow), flow] as const));
      for (const expected of sample.flows) {
        const got = must(seen.get(conversation(expected)), `a flow for ${conversation(expected)}`);
        if (expected.protocol === "udp") {
          // The quiet chatter that follows the scenario joins the DNS exchanges it resembles.
          expect(got.packetsOut, `packets out of ${conversation(expected)}`).toBeGreaterThanOrEqual(expected.packetsOut);
          expect(got.packetsIn, `packets in of ${conversation(expected)}`).toBeGreaterThanOrEqual(expected.packetsIn);
        } else {
          expect(shapeOf(got), `the flow ${conversation(expected)}`).toEqual(shapeOf(expected));
        }
      }
      const closed = must(stored.find((flow) => flow.tcp_flags === 0x1b), "the one connection that opened and closed");
      expect(rowOf(closed)[8], "a connection both sides closed").toBe("Closed");
      expect(await readFlowTable(page, stored.length), "the table against the API, row for row").toEqual(
        stored.map(rowOf),
      );
    });

    await test.step("no capture remains: a second stop is refused and the single slot is free again", async () => {
      const done = must(finished, "the finished session");
      expect(await refusalOf(await stopCapture(request)), "a stop with nothing running").toMatchObject({
        status: 409,
        code: "capture_not_running",
      });
      expect(await fetchStatus(request)).toMatchObject({ state: "stopped", busy: false, session_id: first });

      await live.getByLabel("Interface", { exact: true }).selectOption(quiet.id);
      await live.getByRole("button", { name: "Start capture" }).click();
      await expect(stateBadge(live, "Running")).toBeVisible();
      await expect(live.getByText(`Capturing on ${quiet.name}. The figures below update as packets arrive.`)).toBeVisible();
      const status = await settledStatus(request);
      expect(status, "the API's account of the second capture").toMatchObject({
        state: "running",
        interface: quiet.name,
        busy: false,
      });
      second = must(status.session_id, "a session for the second capture");
      expect(second, "a new session, not the old one").not.toBe(first);

      // Long enough for the office LAN to have delivered more traffic, had its capture been left running.
      await expect
        .poll(async () => (await fetchSession(request, second)).packets_total, {
          message: "the quiet link has carried its first packets",
          timeout: 60_000,
        })
        .toBeGreaterThanOrEqual(2);
      expect(await fetchSession(request, first), "the first session while the second capture ran").toMatchObject({
        status: done.status,
        ended_at: done.ended_at,
        packets_total: done.packets_total,
        bytes_total: done.bytes_total,
        flows_total: done.flows_total,
        alerts_total: done.alerts_total,
      });

      await live.getByRole("button", { name: "Stop capture" }).click();
      await expect(stateBadge(live, "Stopped")).toBeVisible();
      expect(stops.count, "stop requests the page made").toBe(2);
      expect(await fetchStatus(request)).toMatchObject({ state: "stopped", busy: false, session_id: second });
      expect(await refusalOf(await stopCapture(request)), "a second stop").toMatchObject({
        status: 409,
        code: "capture_not_running",
      });
    });

    await test.step("deleting both sessions through the page returns the console to ready", async () => {
      for (const [id, entry] of [
        [first, lan],
        [second, quiet],
      ] as const) {
        const stats = await fetchSession(request, id);
        await history.getByRole("button", { name: `Delete session ${entry.name}`, exact: true }).click();
        await expect(dialog).toBeVisible();
        await expect(fact(dialog, "Live capture:")).toHaveText(entry.name);
        await expect(fact(dialog, "Contains:")).toHaveText(
          `${counted(stats.packets_total, "packet")}, ${counted(stats.flows_total, "flow")}, ${counted(stats.alerts_total, "alert")}`,
        );
        await dialog.getByRole("button", { name: "Delete session", exact: true }).click();
        await expect(dialog).toBeHidden();
        await expect(historyRow(page, `Live capture ${entry.name}`)).toHaveCount(0);
        expect(await statusOf(request, `/api/v1/network/sessions/${id}`), `${entry.name} after deleting it`).toBe(404);
        if (id === first) {
          expect(await fetchStatus(request), "the status while the second session is the last one").toMatchObject({
            state: "stopped",
            session_id: second,
          });
        }
      }
      await expect.poll(async () => (await fetchStatus(request)).state).toBe("ready");
      expect(await fetchStatus(request)).toMatchObject({ state: "ready", interface: null, session_id: null, busy: false });
      await expect(stateBadge(live, "Ready")).toBeVisible();
      await expect(panel(page, "Session")).toContainText("No session is open yet.");

      for (const id of [first, second]) {
        expect(
          (await auditOfSession(id)).filter((row) => LIFECYCLE.includes(row.action)),
          "what the audit log holds about the capture",
        ).toEqual(LIFECYCLE.map((action) => ({ action, result: "success" })));
      }
    });
  });

  test("a start or a stop that the server refuses is explained, and the page then shows what is true", async ({
    page,
    request,
    guard,
  }) => {
    test.setTimeout(120_000);
    guard.expectStatus(409);
    // The page is kept one step behind the server, as a page that has been open for a while would be.
    let believed = await fetchStatus(request);
    await page.route("**/api/v1/network/status", (route) => route.fulfill({ json: believed }));
    await openNetwork(page);
    const live = liveCapture(page);
    const refresh = page.getByRole("button", { name: "Refresh", exact: true });

    await test.step("a start is refused because a capture is already running, and the page says so", async () => {
      expect((await startCapture(request, "simulated-lan")).status(), "a capture started elsewhere").toBe(200);
      await live.getByRole("button", { name: "Start capture" }).click();
      const notice = live.getByRole("alert").filter({ hasText: "A capture is already running" });
      await expect(notice).toContainText(
        "Only one live capture can run at a time, and one is already running. Stop it, or wait until it ends, before starting another.",
      );
      expect((await fetchSessions(request)).total, "sessions after the refused start").toBe(1);

      believed = await fetchStatus(request);
      await refresh.click();
      await expect(stateBadge(live, "Running")).toBeVisible();
    });

    await test.step("a stop is refused because nothing of the caller's is running any more, and the page says so", async () => {
      expect((await stopCapture(request)).status(), "the capture stopped elsewhere").toBe(200);
      await live.getByRole("button", { name: "Stop capture" }).click();
      const notice = live.getByRole("alert").filter({ hasText: "No capture to stop" });
      await expect(notice).toContainText("None of your live captures is running. It may have ended already.");

      believed = await fetchStatus(request);
      await refresh.click();
      await expect(stateBadge(live, "Stopped")).toBeVisible();
      await expect(live.getByText("The capture is stopped.")).toBeVisible();
    });
  });
});

// ---- Data the page cannot trust -----------------------------------------------------------------

/** Says what the API's text would read if someone with bad intent had written it: `key` is the field, `original` its true value. */
type Say = (key: string, original: string) => string;

/** The strings of the network API that a person could have influenced. Ids, counts, times and enumerations are left alone. */
const TEXT_KEYS = new Set([
  "source_label",
  "interface",
  "name",
  "description",
  "title",
  "explanation",
  "unit",
  "detail",
  "rule_id",
  "rule_name",
  "protocol",
  "display_name",
  "verdict",
  "address",
  "src_ip",
  "dst_ip",
  "close_reason",
  "message",
  "classification",
]);
const TEXT_LISTS = new Set(["addresses", "peers", "protocols", "tcp_flag_names"]);

function taintedEvidence(evidence: object, say: Say): Record<string, unknown> {
  const leaf = (value: unknown): unknown => {
    if (typeof value === "string") return say("evidence", value);
    if (Array.isArray(value)) return value.map((item: unknown) => leaf(item));
    if (typeof value === "object" && value !== null) {
      return Object.fromEntries(Object.entries(value).map(([name, item]) => [name, leaf(item)]));
    }
    return value;
  };
  const changed = leaf(evidence);
  const known = typeof changed === "object" && changed !== null ? Object.entries(changed) : [];
  return Object.fromEntries([...known, [say("evidence_key", "extra"), say("evidence", "extra")]]);
}

function tainted(value: unknown, key: string, say: Say): unknown {
  if (typeof value === "string") return TEXT_KEYS.has(key) ? say(key, value) : value;
  if (Array.isArray(value)) {
    return value.map((item: unknown) =>
      typeof item === "string" ? (TEXT_LISTS.has(key) ? say(key, item) : item) : tainted(item, key, say),
    );
  }
  if (typeof value !== "object" || value === null) return value;
  if (key === "evidence") return taintedEvidence(value, say);
  const entries = Object.entries(value);
  if (key === "alerts_by_rule") return Object.fromEntries(entries.map(([rule, count]) => [say("rule_id", rule), count]));
  return Object.fromEntries(entries.map(([name, item]) => [name, tainted(item, name, say)]));
}

function recordOf(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? Object.fromEntries(Object.entries(value)) : {};
}

/** Serves the network API with its text replaced by `say`, and with the messages a healthy API leaves empty filled in. */
async function serveTainted(page: Page, say: Say): Promise<void> {
  await page.route("**/api/v1/network/**", async (route) => {
    if (route.request().method() !== "GET") return route.fallback();
    const response = await route.fetch();
    if (!response.ok()) return route.fulfill({ response });
    const path = new URL(route.request().url()).pathname;
    const changed = tainted(await response.json(), "", say);
    if (path.endsWith("/network/status")) {
      return route.fulfill({
        status: response.status(),
        json: { ...recordOf(changed), interface: say("interface", "status"), message: say("message", "status") },
      });
    }
    if (/\/network\/sessions\/[^/]+$/.test(path)) {
      return route.fulfill({ status: response.status(), json: { ...recordOf(changed), message: say("message", "detail") } });
    }
    return route.fulfill({ status: response.status(), json: changed });
  });
}

const VARIANTS: ReadonlyArray<{ name: string; words: (field: string) => string }> = [
  ...KINDS.map((kind) => ({ name: kind, words: (field: string) => ATTACKS.text(field, kind) })),
  { name: "bidi", words: (field: string) => `${field}\u202E gnp.exe \u2066\u2069\u200F` },
];

test("text from the network API is shown as text and never run, whatever it contains", async ({ page, request }) => {
  test.setTimeout(180_000);
  watchDialogs(page);
  const session = await analyseSample(request, `hostile-${uniqueTag()}.pcap`);
  const label = must(session.source_label, "the name the capture was uploaded under");
  const { interfaces } = await fetchInterfaces(request);
  const rules = await fetchRules(request);
  const { items: alerts } = await fetchAlerts(request, session.id);
  const { items: flows } = await fetchFlows(request, session.id);
  let words = VARIANTS[0]?.words ?? ((field: string) => field);
  const say: Say = (key, original) => words(`${key}_${original}`);
  await serveTainted(page, say);

  const summary = panel(page, "Session summary");
  const live = liveCapture(page);
  const firstAlert = must(alerts[0], "an alert");
  const firstFlow = must(flows[0], "a flow");
  const firstRule = must(rules[0], "a detection rule");
  const talker = must(session.top_sources[0], "a top talker");
  const protocol = must(session.protocols[0], "a protocol");

  for (const variant of VARIANTS) {
    words = variant.words;
    await test.step(`${variant.name}: every name, label, address and message is plain text`, async () => {
      await openSession(page, session.id);
      await expect(panel(page, "Session history")).toContainText(say("source_label", label));
      await expect(fact(summary, "Source")).toHaveText(`Capture file: ${say("source_label", label)}`);
      await expect(fact(summary, "Alerts by rule")).toContainText(say("rule_id", "NET-001"));
      await expect(fact(live, "Capture interface")).toHaveText(say("interface", "status"));
      await expect(live.getByRole("option")).toHaveText(
        interfaces.map((entry) => `${say("name", entry.name)} - ${say("description", entry.description)}`),
      );
      await expect(live.getByText(/^Addresses: /).first()).toHaveText(
        `Addresses: ${must(interfaces[0], "an interface").addresses.map((address) => say("addresses", address)).join(", ")}`,
      );
      await expect(panel(page, "Alerts")).toContainText(say("title", firstAlert.title));
      await expect(panel(page, "Alerts")).toContainText(say("explanation", firstAlert.explanation));
      await expect(panel(page, "Flows").locator("tbody tr").first()).toContainText(say("src_ip", firstFlow.src_ip), {
        ignoreCase: true,
      });
      await expect(panel(page, "External IP addresses").getByRole("heading", { level: 3 })).toHaveText(
        session.external_ips.map((external) => say("address", external.address)),
      );
      await expect(panel(page, "Top talkers")).toContainText(say("address", talker.address));
      await expect(panel(page, "Protocol distribution")).toContainText(say("protocol", protocol.protocol), {
        ignoreCase: true,
      });
      await expect(panel(page, "Detection rules")).toContainText(say("title", firstRule.title));
      await expectInert(page, `the session, with every name written as ${variant.name}`);
    });

    await test.step(`${variant.name}: the evidence behind an alert and the confirmation to delete are plain text too`, async () => {
      const toggle = panel(page, "Alerts").getByRole("button", { name: /^Evidence for rule / }).first();
      await toggle.click();
      await expect(panel(page, "Alerts")).toContainText(say("evidence", "extra").slice(0, 24));
      await expectInert(page, `the evidence, written as ${variant.name}`);

      await summary.getByRole("button", { name: "Delete session", exact: true }).click();
      const dialog = page.getByRole("dialog", { name: "Delete this session?" });
      await expect(fact(dialog, "Capture file:")).toHaveText(say("source_label", label));
      await expectInert(page, `the confirmation to delete, written as ${variant.name}`);
      await dialog.getByRole("button", { name: "Cancel" }).click();
      await expect(dialog).toBeHidden();
    });
  }
  expect((await fetchSessions(request)).total, "the session, which nothing in the page may have deleted").toBeGreaterThan(0);
});

test("an error from the API is shown as text, with its reference, and nothing in it runs", async ({ page, guard }) => {
  guard.expectStatus(500);
  watchDialogs(page);
  const message = ATTACKS.text("message");
  const reference = ATTACKS.text("correlation_id", "handler");
  await page.route("**/api/v1/network/**", (route) =>
    route.fulfill({ status: 500, json: { error: { code: "internal_error", message, correlation_id: reference } } }),
  );
  await page.goto("/network");
  await expect(page.getByRole("heading", { name: "Network", level: 1 })).toBeVisible();
  await expect(page.getByText("The API reported an error").first()).toBeVisible();
  await expect(page.getByText(message).first()).toBeVisible();
  await expect(page.getByText(reference).first()).toBeVisible();
  await expectInert(page, "the error state of the network screen");
});

// ---- Layout and accessibility -------------------------------------------------------------------

type Screen = (typeof SCREENS)[number];

/** The idle console, one session with its evidence open, and the confirmation to delete it, at one screen size. */
async function expectLaidOut(page: Page, id: string, screen: Screen, what: string): Promise<void> {
  const size = `${what} at ${screen.width} px`;
  await page.setViewportSize(screen);
  await openNetwork(page);
  await expectFits(page, `the console, ${size}`);
  await expectTextInPlace(page, `the console, ${size}`);

  await openSession(page, id);
  await expectFits(page, `the session, ${size}`);
  await panel(page, "Alerts").getByRole("button", { name: /^Evidence for rule / }).first().click();
  await expectFits(page, `the evidence, ${size}`);
  await expectTextInPlace(page, `the session with its evidence, ${size}`);

  await panel(page, "Session summary").getByRole("button", { name: "Delete session", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Delete this session?" });
  await expect(dialog).toBeVisible();
  await expectOnScreen(dialog, screen);
  await dialog.getByRole("button", { name: "Cancel" }).click();
  await expect(dialog).toBeHidden();
}

test("the console, a session and the confirmation to delete fit every screen width", async ({ page, request }) => {
  test.setTimeout(180_000);
  const session = await analyseSample(request, `layout-${uniqueTag()}.pcap`);
  for (const screen of SCREENS) await expectLaidOut(page, session.id, screen, "the capture");
});

test("huge unbroken strings from the API stay inside their boxes", async ({ page, request }) => {
  test.setTimeout(180_000);
  const session = await analyseSample(request, `long-${uniqueTag()}.pcap`);
  // What people, the operating system and the providers decide: names of files and interfaces, provider words and
  // what the traffic carried. The rule ids, titles and units are the server's own vocabulary.
  const { interfaces } = await fetchInterfaces(request);
  const decided = new Set(["source_label", "interface", "message", "verdict", "evidence"]);
  const named = new Set(interfaces.flatMap((entry) => [entry.name, entry.description, ...entry.addresses]));
  await serveTainted(page, (key, original) =>
    decided.has(key) || named.has(original) ? LONG.text(`${key}_${original}`) : original,
  );
  for (const screen of [SCREENS[0], SCREENS[3]]) await expectLaidOut(page, session.id, screen, "huge strings");
});

test("the network screen has no accessibility violations in any of its states", async ({ page, request, guard }) => {
  test.setTimeout(300_000);
  const live = liveCapture(page);

  await test.step("idle, with no history", async () => {
    await openNetwork(page);
    await expect(page.getByText("No session is open yet.")).toBeVisible();
    await expectAccessible(page, "the idle console");
  });

  await test.step("running, with traffic arriving", async () => {
    expect((await startCapture(request, "simulated-lan")).status()).toBe(200);
    try {
      const { session_id: id } = await settledStatus(request);
      await expect
        .poll(async () => (await fetchSession(request, must(id, "the running session"))).packets_total, { timeout: 30_000 })
        .toBeGreaterThan(0);
      await openNetwork(page);
      await expect(stateBadge(live, "Running")).toBeVisible();
      await expectAccessible(page, "the console while a capture runs");
    } finally {
      await stopCapture(request);
      await settledStatus(request);
    }
  });

  const session = await analyseSample(request, `axe-${uniqueTag()}.pcap`);
  await test.step("a session, with its flows and alerts", async () => {
    await openSession(page, session.id);
    await expect(panel(page, "Flows").locator("tbody tr").first()).toBeVisible();
    await expect(panel(page, "Alerts").getByRole("button", { name: /^Evidence for rule / }).first()).toBeVisible();
    await expectAccessible(page, "a session with its flows and alerts");
  });

  await test.step("a session, with the evidence behind an alert open", async () => {
    await openSession(page, session.id);
    await panel(page, "Alerts").getByRole("button", { name: /^Evidence for rule / }).first().click();
    await expectAccessible(page, "a session with evidence open");
  });

  await test.step("the confirmation to delete a session", async () => {
    await openSession(page, session.id);
    await panel(page, "Session summary").getByRole("button", { name: "Delete session", exact: true }).click();
    await expect(page.getByRole("dialog", { name: "Delete this session?" })).toBeVisible();
    await expectAccessible(page, "the confirmation to delete");
  });

  await test.step("a phone, with a session open", async () => {
    await page.setViewportSize({ width: 390, height: 844 });
    await openSession(page, session.id);
    await expectFits(page, "a session on a phone");
    await expectAccessible(page, "a session on a phone");
  });

  await test.step("an API that answers every request with an error", async () => {
    guard.expectStatus(500);
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.route("**/api/v1/network/**", (route) =>
      route.fulfill({
        status: 500,
        json: { error: { code: "internal_error", message: "The service failed.", correlation_id: "e2e-network-error" } },
      }),
    );
    await page.goto("/network");
    await expect(page.getByText("The API reported an error").first()).toBeVisible();
    await expectAccessible(page, "the network screen when the API fails");
  });
});
