import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { type APIRequestContext, type APIResponse, expect } from "@playwright/test";

import type {
  AlertPage,
  DetectionRule,
  Flow,
  FlowPage,
  InterfaceList,
  NetworkStatus,
  SessionDetail,
  SessionPage,
} from "../src/types/network";
import { istText } from "./files-api";
import { must } from "./text";

/**
 * What the Network journeys need besides the page: reads and writes of the API (used to set a test
 * up, to clear it away and as an oracle for what the page should say), the audit trail in the demo
 * database, and the synthetic capture file read byte by byte, so that the numbers a page shows are
 * checked against the file itself and not against the app's own reading of it. Nothing here
 * imports the app's helpers, so a mistake in the app shows up as a failing test.
 */

const API = "/api/v1/network";

const DEMO_DB = resolve(import.meta.dirname, "..", "..", "backend", ".demo", "e2e.db");

/** Synthetic test data written by backend/devtools/synthetic_network.py: no real traffic, no real host. */
export const CAPTURE_PATH = resolve(import.meta.dirname, "data", "synthetic-network.pcap");
export const CAPTURE_NAME = "synthetic-network.pcap";

// ---- The API ----------------------------------------------------------------------------------

async function getJson<T>(request: APIRequestContext, path: string): Promise<T> {
  const response = await request.get(path);
  if (!response.ok()) throw new Error(`GET ${path} answered ${response.status()}`);
  return (await response.json()) as T;
}

export function fetchStatus(request: APIRequestContext): Promise<NetworkStatus> {
  return getJson<NetworkStatus>(request, `${API}/status`);
}

export function fetchInterfaces(request: APIRequestContext): Promise<InterfaceList> {
  return getJson<InterfaceList>(request, `${API}/interfaces`);
}

export function fetchSessions(request: APIRequestContext): Promise<SessionPage> {
  return getJson<SessionPage>(request, `${API}/sessions?limit=100`);
}

export function fetchSession(request: APIRequestContext, id: string): Promise<SessionDetail> {
  return getJson<SessionDetail>(request, `${API}/sessions/${id}`);
}

export function fetchFlows(request: APIRequestContext, id: string): Promise<FlowPage> {
  return getJson<FlowPage>(request, `${API}/sessions/${id}/flows?limit=200`);
}

export function fetchAlerts(request: APIRequestContext, id: string): Promise<AlertPage> {
  return getJson<AlertPage>(request, `${API}/sessions/${id}/alerts?limit=200`);
}

export function fetchRules(request: APIRequestContext): Promise<DetectionRule[]> {
  return getJson<DetectionRule[]>(request, `${API}/rules`);
}

export function startCapture(request: APIRequestContext, interfaceId: string): Promise<APIResponse> {
  return request.post(`${API}/capture/start`, { data: { interface: interfaceId } });
}

export function stopCapture(request: APIRequestContext): Promise<APIResponse> {
  return request.post(`${API}/capture/stop`);
}

/** The code and message of an error answer, which is all a person is told. */
export interface Refusal {
  status: number;
  code: string;
  message: string;
}

export async function refusalOf(response: APIResponse): Promise<Refusal> {
  const body = (await response.json()) as { error: { code: string; message: string } };
  return { status: response.status(), code: body.error.code, message: body.error.message };
}

/** Deletes a session, and is happy when a test has already deleted it through the page. */
export async function removeSession(request: APIRequestContext, id: string): Promise<void> {
  const response = await request.delete(`${API}/sessions/${id}`);
  if (response.status() !== 204 && response.status() !== 404) {
    throw new Error(`DELETE /network/sessions answered ${response.status()}`);
  }
}

/** Waits until a capture has finished starting or stopping, and says where it ended up. */
export async function settledStatus(request: APIRequestContext): Promise<NetworkStatus> {
  let status = await fetchStatus(request);
  await expect
    .poll(
      async () => {
        status = await fetchStatus(request);
        return status.state;
      },
      { message: "the capture is neither starting nor stopping" },
    )
    .not.toMatch(/^(starting|stopping)$/);
  return status;
}

/** Sends a capture file the way the page does: the raw bytes, with the name in a header. */
export function postCapture(request: APIRequestContext, name: string, data: Buffer): Promise<APIResponse> {
  return request.post(`${API}/pcap`, {
    headers: { "content-type": "application/octet-stream", "x-file-name": encodeURIComponent(name) },
    data,
  });
}

/**
 * Sends a capture file to the API the way the page does and waits until it has been analysed and
 * its public addresses have been looked up, so that what a test reads next no longer changes.
 */
export async function analyseViaApi(request: APIRequestContext, name: string, data: Buffer): Promise<SessionDetail> {
  const response = await postCapture(request, name, data);
  if (response.status() !== 202) throw new Error(`POST /network/pcap answered ${response.status()}`);
  const { id } = (await response.json()) as SessionDetail;
  await expect
    .poll(
      async () => {
        const session = await fetchSession(request, id);
        return session.status === "completed" && session.enrichment.pending === 0;
      },
      { message: "the analysis and the lookups are finished", timeout: 30_000 },
    )
    .toBe(true);
  return fetchSession(request, id);
}

export async function analyseSample(request: APIRequestContext, name = CAPTURE_NAME): Promise<SessionDetail> {
  return analyseViaApi(request, name, await readFile(CAPTURE_PATH));
}

// ---- The audit trail --------------------------------------------------------------------------

export interface AuditRow {
  action: string;
  result: string;
}

/** What the audit log holds about one session, oldest first. Rows are only ever added. */
export async function auditOfSession(sessionId: string): Promise<AuditRow[]> {
  // Loaded when needed, so a Node that lacks the module only breaks the test that uses it.
  const { DatabaseSync } = await import("node:sqlite");
  const database = new DatabaseSync(DEMO_DB);
  try {
    database.exec("PRAGMA busy_timeout = 5000");
    const rows = database
      .prepare("SELECT action, result FROM audit_logs WHERE target = ? ORDER BY id")
      .all(`network-session:${sessionId}`);
    return rows.map((row) => ({ action: String(row["action"]), result: String(row["result"]) }));
  } finally {
    database.close();
  }
}

// ---- Words and numbers, worked out by hand ----------------------------------------------------

/** "1.50 MB", "5.81 KB" or "790 B": two decimals above a kilobyte, steps of 1024. */
export function sizeText(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

/** "10.20.30.40:80" or "[fd00::1]:80"; without a port, the plain address. */
export function endpointText(address: string, port: number | null): string {
  if (port === null) return address;
  return address.includes(":") ? `[${address}]:${port}` : `${address}:${port}`;
}

/** The "A to B" that names a flow in the table. */
export function flowName(flow: Pick<Flow, "src_ip" | "src_port" | "dst_ip" | "dst_port">): string {
  return `${endpointText(flow.src_ip, flow.src_port)} to ${endpointText(flow.dst_ip, flow.dst_port)}`;
}

/** Whether an address is one a person on the internet could be at: none of the reserved ranges. */
export function isPublic(address: string): boolean {
  if (address.includes(":")) {
    const first = Number.parseInt(address.split(":")[0] || "0", 16);
    // Global unicast is 2000::/3; 2001:db8::/32 is reserved for documentation.
    return (first & 0xe000) === 0x2000 && !address.toLowerCase().startsWith("2001:db8:");
  }
  const [a = 0, b = 0, c = 0] = address.split(".").map(Number);
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 100 && (b & 0xc0) === 64) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 0 && (c === 0 || c === 2)) return false;
  if (a === 192 && b === 168) return false;
  if (a === 198 && (b === 18 || b === 19)) return false;
  if (a === 198 && b === 51 && c === 100) return false;
  if (a === 203 && b === 0 && c === 113) return false;
  return true;
}

// ---- The capture file, read byte by byte ------------------------------------------------------

export interface Packet {
  protocol: "tcp" | "udp" | "icmp";
  src: string;
  dst: string;
  srcPort: number | null;
  dstPort: number | null;
  /** The TCP flag bits, or null for a packet that is not TCP. */
  flags: number | null;
  /** The whole frame, headers included, as the capture file records it. */
  bytes: number;
  seconds: number;
}

export interface Capture {
  /** Packets that are IP traffic. */
  packets: Packet[];
  /** Frames without an IP header, such as ARP. */
  nonIp: number;
}

function ipv4Text(frame: Buffer, offset: number): string {
  return [0, 1, 2, 3].map((index) => frame.readUInt8(offset + index)).join(".");
}

/** The shortest form of an IPv6 address: lower case, no leading zeros, the longest run of zeros as "::". */
function ipv6Text(frame: Buffer, offset: number): string {
  const groups = Array.from({ length: 8 }, (_, index) => frame.readUInt16BE(offset + index * 2));
  let bestStart = -1;
  let bestLength = 0;
  for (let start = 0; start < groups.length; ) {
    if (groups[start] !== 0) {
      start += 1;
      continue;
    }
    let end = start;
    while (end < groups.length && groups[end] === 0) end += 1;
    if (end - start > bestLength) {
      bestStart = start;
      bestLength = end - start;
    }
    start = end;
  }
  const hex = groups.map((group) => group.toString(16));
  if (bestLength < 2) return hex.join(":");
  return `${hex.slice(0, bestStart).join(":")}::${hex.slice(bestStart + bestLength).join(":")}`;
}

/** Reads a classic little-endian PCAP file of Ethernet frames: the format the sample is written in. */
export function parseCapture(data: Buffer): Capture {
  if (data.readUInt32LE(0) !== 0xa1b2c3d4) throw new Error("Expected a classic, little-endian PCAP file");
  if (data.readUInt32LE(20) !== 1) throw new Error("Expected Ethernet frames");
  const capture: Capture = { packets: [], nonIp: 0 };
  let offset = 24;
  while (offset < data.length) {
    const seconds = data.readUInt32LE(offset) + data.readUInt32LE(offset + 4) / 1e6;
    const length = data.readUInt32LE(offset + 8);
    const frame = data.subarray(offset + 16, offset + 16 + length);
    offset += 16 + length;

    const kind = frame.readUInt16BE(12);
    let protocol: number;
    let src: string;
    let dst: string;
    let transport: number;
    if (kind === 0x0800) {
      protocol = frame.readUInt8(14 + 9);
      src = ipv4Text(frame, 14 + 12);
      dst = ipv4Text(frame, 14 + 16);
      transport = 14 + (frame.readUInt8(14) & 0x0f) * 4;
    } else if (kind === 0x86dd) {
      protocol = frame.readUInt8(14 + 6);
      src = ipv6Text(frame, 14 + 8);
      dst = ipv6Text(frame, 14 + 24);
      transport = 14 + 40;
    } else {
      capture.nonIp += 1;
      continue;
    }
    const base = { src, dst, bytes: length, seconds };
    if (protocol === 6) {
      capture.packets.push({
        ...base,
        protocol: "tcp",
        srcPort: frame.readUInt16BE(transport),
        dstPort: frame.readUInt16BE(transport + 2),
        flags: frame.readUInt8(transport + 13),
      });
    } else if (protocol === 17) {
      capture.packets.push({
        ...base,
        protocol: "udp",
        srcPort: frame.readUInt16BE(transport),
        dstPort: frame.readUInt16BE(transport + 2),
        flags: null,
      });
    } else if (protocol === 1) {
      capture.packets.push({ ...base, protocol: "icmp", srcPort: null, dstPort: null, flags: null });
    } else {
      throw new Error(`The sample holds an IP protocol this reader does not know: ${protocol}`);
    }
  }
  return capture;
}

export async function readSample(): Promise<Capture> {
  return parseCapture(await readFile(CAPTURE_PATH));
}

/** One conversation, from the side that spoke first. */
export interface FlowFact {
  protocol: string;
  src: string;
  srcPort: number | null;
  dst: string;
  dstPort: number | null;
  packetsOut: number;
  packetsIn: number;
  bytesOut: number;
  bytesIn: number;
  flags: number | null;
  /** Seconds since 1970 of the first and the last packet. */
  first: number;
  last: number;
}

/** Packets that share both endpoints and the protocol, whichever way they go, are one flow. */
export function flowsOf(packets: readonly Packet[]): FlowFact[] {
  const flows = new Map<string, FlowFact>();
  for (const packet of packets) {
    const ends = [`${packet.src}|${packet.srcPort}`, `${packet.dst}|${packet.dstPort}`].sort();
    const key = `${packet.protocol}|${ends.join("|")}`;
    const flow = flows.get(key);
    if (flow === undefined) {
      flows.set(key, {
        protocol: packet.protocol,
        src: packet.src,
        srcPort: packet.srcPort,
        dst: packet.dst,
        dstPort: packet.dstPort,
        packetsOut: 1,
        packetsIn: 0,
        bytesOut: packet.bytes,
        bytesIn: 0,
        flags: packet.flags,
        first: packet.seconds,
        last: packet.seconds,
      });
      continue;
    }
    flow.first = Math.min(flow.first, packet.seconds);
    flow.last = Math.max(flow.last, packet.seconds);
    if (packet.src === flow.src && packet.srcPort === flow.srcPort) {
      flow.packetsOut += 1;
      flow.bytesOut += packet.bytes;
    } else {
      flow.packetsIn += 1;
      flow.bytesIn += packet.bytes;
    }
    if (flow.flags !== null && packet.flags !== null) flow.flags |= packet.flags;
  }
  return [...flows.values()];
}

/** What the API calls a flow, in the terms of `FlowFact`. */
export function factOf(flow: Flow): FlowFact {
  return {
    protocol: flow.protocol,
    src: flow.src_ip,
    srcPort: flow.src_port,
    dst: flow.dst_ip,
    dstPort: flow.dst_port,
    packetsOut: flow.packets_out,
    packetsIn: flow.packets_in,
    bytesOut: flow.bytes_out,
    bytesIn: flow.bytes_in,
    flags: flow.tcp_flags,
    first: Date.parse(flow.first_seen) / 1000,
    last: Date.parse(flow.last_seen) / 1000,
  };
}

export function byConversation(first: FlowFact, second: FlowFact): number {
  const key = (flow: FlowFact): string => JSON.stringify([flow.protocol, flow.src, flow.srcPort, flow.dst, flow.dstPort]);
  return key(first).localeCompare(key(second));
}

export interface Talker {
  address: string;
  packets: number;
  bytes: number;
}

/** The addresses that sent (or received) the most data, busiest first. */
export function talkers(packets: readonly Packet[], side: "src" | "dst"): Talker[] {
  const totals = new Map<string, Talker>();
  for (const packet of packets) {
    const address = packet[side];
    const talker = totals.get(address) ?? { address, packets: 0, bytes: 0 };
    talker.packets += 1;
    talker.bytes += packet.bytes;
    totals.set(address, talker);
  }
  return [...totals.values()].sort((first, second) => second.bytes - first.bytes);
}

/** Every address in the capture, once. */
export function addressesOf(packets: readonly Packet[]): string[] {
  return [...new Set(packets.flatMap((packet) => [packet.src, packet.dst]))];
}

/** "DD-MM-YYYY hh:mm:ss AM IST" for a time in seconds since 1970, found without the app. */
export function istOfSeconds(seconds: number): string {
  return istText(new Date(Math.round(seconds * 1000)).toISOString());
}

const FLAG_NAMES = ["FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"] as const;

/** The TCP flag bits that are set, by name and in bit order, as the flags column lists them. */
export function flagNames(bits: number): string[] {
  return FLAG_NAMES.filter((_, index) => (bits & (1 << index)) !== 0);
}

/** A source that tried many different destination ports. */
export interface Scan {
  source: string;
  /** The ports it had tried when it reached the threshold, lowest first. */
  ports: number[];
  targets: string[];
  /** The first connection attempt, and the one that reached the threshold. */
  first: number;
  last: number;
}

/**
 * Which sources tried `threshold` different destination ports. A connection attempt is the first
 * packet of a conversation, when it is a SYN that acknowledges nothing or is not TCP at all. The
 * time window the app applies is left out: the sample is over within five seconds.
 */
export function portScans(packets: readonly Packet[], threshold: number): Scan[] {
  const opened = new Set<string>();
  const attempts = new Map<string, Packet[]>();
  const scans: Scan[] = [];
  const done = new Set<string>();
  for (const packet of [...packets].sort((earlier, later) => earlier.seconds - later.seconds)) {
    const ends = [`${packet.src}|${packet.srcPort}`, `${packet.dst}|${packet.dstPort}`].sort();
    const conversation = `${packet.protocol}|${ends.join("|")}`;
    if (opened.has(conversation)) continue;
    opened.add(conversation);
    if (packet.dstPort === null) continue;
    if (packet.flags !== null && (packet.flags & 0x12) !== 0x02) continue;
    const tried = attempts.get(packet.src) ?? [];
    tried.push(packet);
    attempts.set(packet.src, tried);
    const ports = new Set(tried.map((attempt) => attempt.dstPort));
    if (ports.size < threshold || done.has(packet.src)) continue;
    done.add(packet.src);
    scans.push({
      source: packet.src,
      ports: [...ports].flatMap((port) => (port === null ? [] : [port])).sort((low, high) => low - high),
      targets: [...new Set(tried.map((attempt) => attempt.dst))],
      first: must(tried[0]).seconds,
      last: packet.seconds,
    });
  }
  return scans;
}

/** One TCP segment of a capture that a test writes itself. */
export interface Segment {
  src: string;
  dst: string;
  srcPort: number;
  dstPort: number;
  flags: number;
  payload: Buffer;
}

function internetChecksum(data: Buffer): number {
  const even = data.length % 2 === 0 ? data : Buffer.concat([data, Buffer.alloc(1)]);
  let sum = 0;
  for (let index = 0; index < even.length; index += 2) sum += even.readUInt16BE(index);
  while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
  return ~sum & 0xffff;
}

function ipv4Bytes(address: string): Buffer {
  return Buffer.from(address.split(".").map(Number));
}

/**
 * A classic PCAP file of Ethernet, IPv4 and TCP, one frame per segment and 100 ms apart, with
 * correct checksums. The sample carries empty packets only, so a test that wants to show that
 * what packets carry is never kept writes its own.
 */
export function buildCapture(segments: readonly Segment[], start: number): Buffer {
  const header = Buffer.alloc(24);
  header.writeUInt32LE(0xa1b2c3d4, 0);
  header.writeUInt16LE(2, 4);
  header.writeUInt16LE(4, 6);
  header.writeUInt32LE(65535, 16);
  header.writeUInt32LE(1, 20);

  const records = segments.map((segment, index) => {
    const tcp = Buffer.alloc(20 + segment.payload.length);
    tcp.writeUInt16BE(segment.srcPort, 0);
    tcp.writeUInt16BE(segment.dstPort, 2);
    tcp.writeUInt32BE(1000 + index, 4);
    tcp.writeUInt8(5 << 4, 12);
    tcp.writeUInt8(segment.flags, 13);
    tcp.writeUInt16BE(65535, 14);
    segment.payload.copy(tcp, 20);
    const pseudo = Buffer.alloc(12);
    ipv4Bytes(segment.src).copy(pseudo, 0);
    ipv4Bytes(segment.dst).copy(pseudo, 4);
    pseudo.writeUInt8(6, 9);
    pseudo.writeUInt16BE(tcp.length, 10);
    tcp.writeUInt16BE(internetChecksum(Buffer.concat([pseudo, tcp])), 16);

    const ip = Buffer.alloc(20);
    ip.writeUInt8(0x45, 0);
    ip.writeUInt16BE(20 + tcp.length, 2);
    ip.writeUInt16BE(index + 1, 4);
    ip.writeUInt8(64, 8);
    ip.writeUInt8(6, 9);
    ipv4Bytes(segment.src).copy(ip, 12);
    ipv4Bytes(segment.dst).copy(ip, 16);
    ip.writeUInt16BE(internetChecksum(ip), 10);

    const ethernet = Buffer.from([2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 0x08, 0x00]);
    const frame = Buffer.concat([ethernet, ip, tcp]);
    const micros = index * 100_000;
    const record = Buffer.alloc(16);
    record.writeUInt32LE(start + Math.floor(micros / 1_000_000), 0);
    record.writeUInt32LE(micros % 1_000_000, 4);
    record.writeUInt32LE(frame.length, 8);
    record.writeUInt32LE(frame.length, 12);
    return Buffer.concat([record, frame]);
  });
  return Buffer.concat([header, ...records]);
}

/** Every byte the demo database holds, write-ahead log included, to look for something that must not be there. */
export async function demoDatabaseBytes(): Promise<Buffer[]> {
  const files = [DEMO_DB, `${DEMO_DB}-wal`];
  const parts: Buffer[] = [];
  for (const file of files) {
    try {
      parts.push(await readFile(file));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
  }
  return parts;
}
