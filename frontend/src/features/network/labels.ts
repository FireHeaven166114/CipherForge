import type { CaptureSession, CaptureState, Flow, SessionStatus } from "../../types/network";
import { formatCount } from "../intel/format";

export type BadgeTone = "ok" | "warn" | "bad" | "neutral";
export type LedKind = "ok" | "warn" | "bad" | "idle" | "cipher";

export interface StateMeta {
  label: string;
  tone: BadgeTone;
  led: LedKind;
  /** True while the state is changing or work is under way. */
  pulsing: boolean;
}

export const CAPTURE_STATE_META: Readonly<Record<CaptureState, StateMeta>> = {
  not_configured: { label: "Not configured", tone: "warn", led: "warn", pulsing: false },
  ready: { label: "Ready", tone: "ok", led: "ok", pulsing: false },
  starting: { label: "Starting", tone: "neutral", led: "cipher", pulsing: true },
  running: { label: "Running", tone: "ok", led: "ok", pulsing: true },
  stopping: { label: "Stopping", tone: "neutral", led: "cipher", pulsing: true },
  stopped: { label: "Stopped", tone: "neutral", led: "idle", pulsing: false },
  failed: { label: "Failed", tone: "bad", led: "bad", pulsing: false },
  permission_denied: { label: "Permission denied", tone: "bad", led: "bad", pulsing: false },
};

export const SESSION_STATUS_META: Readonly<Record<SessionStatus, StateMeta>> = {
  starting: CAPTURE_STATE_META.starting,
  running: CAPTURE_STATE_META.running,
  stopping: CAPTURE_STATE_META.stopping,
  stopped: CAPTURE_STATE_META.stopped,
  completed: { label: "Completed", tone: "ok", led: "ok", pulsing: false },
  failed: CAPTURE_STATE_META.failed,
  permission_denied: CAPTURE_STATE_META.permission_denied,
};

const ACTIVE_CAPTURE_STATES: readonly CaptureState[] = ["starting", "running", "stopping"];
const ACTIVE_SESSION_STATUSES: readonly SessionStatus[] = ["starting", "running", "stopping"];

/** True while a live capture of the caller's is under way. */
export function isCaptureActive(state: CaptureState): boolean {
  return ACTIVE_CAPTURE_STATES.includes(state);
}

/** True while a session is still being filled: capturing, or analysing a file. */
export function isSessionActive(status: SessionStatus): boolean {
  return ACTIVE_SESSION_STATUSES.includes(status);
}

/** "Idle timeout" for "idle_timeout": a code or key, put into words. */
export function humanize(key: string): string {
  const words = key.replace(/[_-]+/g, " ").trim();
  return words === "" ? key : `${words.charAt(0).toUpperCase()}${words.slice(1)}`;
}

export interface SourceDescription {
  /** "Live capture" or "Capture file". */
  kind: string;
  /** The interface, or the name the file was uploaded under. Plain text only. */
  name: string;
}

export function describeSource(
  session: Pick<CaptureSession, "source_kind" | "source_label" | "interface">,
): SourceDescription {
  return session.source_kind === "live"
    ? { kind: "Live capture", name: session.interface ?? "Unknown interface" }
    : { kind: "Capture file", name: session.source_label ?? "Unnamed file" };
}

const PROTOCOL_NAMES: Readonly<Record<string, string>> = {
  icmpv6: "ICMPv6",
};

/** "TCP", "ICMPv6", "Protocol 47": a protocol name as an analyst writes it. */
export function protocolLabel(protocol: string): string {
  const known = PROTOCOL_NAMES[protocol.toLowerCase()];
  if (known !== undefined) return known;
  const numbered = /^proto-(\d+)$/i.exec(protocol);
  if (numbered?.[1] !== undefined) return `Protocol ${numbered[1]}`;
  return protocol.toUpperCase();
}

/** "192.0.2.10:22", "[2001:db8::1]:443" or just the address when there is no port. */
export function formatEndpoint(address: string, port: number | null): string {
  if (port === null) return address;
  return address.includes(":") ? `[${address}]:${port}` : `${address}:${port}`;
}

export interface CloseReason {
  label: string;
  explanation: string;
}

export const CLOSE_REASONS: Readonly<Record<string, CloseReason>> = {
  idle: { label: "Idle", explanation: "Nothing was seen for longer than the idle timeout." },
  evicted: {
    label: "Evicted",
    explanation: "Closed early to make room, because the table of open flows was full.",
  },
  closed: {
    label: "Closed",
    explanation: "The TCP connection was reset, or both sides closed it.",
  },
  ended: { label: "Session ended", explanation: "Still open when the session ended." },
};

export function closeReasonLabel(reason: string): string {
  return Object.hasOwn(CLOSE_REASONS, reason) ? (CLOSE_REASONS[reason]?.label ?? reason) : humanize(reason);
}

/** The TCP flags seen on a flow, by name ("SYN ACK"), or why there are none. */
export function formatFlags(flow: Pick<Flow, "tcp_flags" | "tcp_flag_names">): string {
  if (flow.tcp_flag_names.length > 0) return flow.tcp_flag_names.join(" ");
  return flow.tcp_flags === null ? "Not TCP" : "None";
}

export function yesNo(value: boolean): string {
  return value ? "Yes" : "No";
}

/** "1 packet", "1,204 packets": a count in full, with its noun in the plural unless the count is one. */
export function countOf(count: number, noun: string): string {
  return `${formatCount(count)} ${count === 1 ? noun : `${noun}s`}`;
}
