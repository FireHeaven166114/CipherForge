import type { NetworkStatus, SessionDetail } from "../../types/network";
import { isCaptureActive, isSessionActive } from "./labels";

/** How often the page asks again while something is changing. */
export const LIVE_POLL_MS = 2_000;
/** And while nothing is: a quiet check that also catches work started from another tab. */
export const IDLE_POLL_MS = 15_000;
/** How often an uploaded capture is asked about until its analysis ends. */
export const PCAP_POLL_MS = 1_500;
/** An analysis keeps running on the server when a poll fails, so a few failures in a row are tolerated. */
export const PCAP_MAX_POLL_FAILURES = 3;

export function statusPollInterval(status: Pick<NetworkStatus, "state" | "analysis">): number {
  return isCaptureActive(status.state) || status.analysis.running ? LIVE_POLL_MS : IDLE_POLL_MS;
}

/** A session still being filled changes every second; so does one waiting for address lookups. */
export function sessionPollInterval(
  session: Pick<SessionDetail, "status" | "enrichment"> | null,
): number {
  if (session === null) return IDLE_POLL_MS;
  return isSessionActive(session.status) || session.enrichment.pending > 0 ? LIVE_POLL_MS : IDLE_POLL_MS;
}
