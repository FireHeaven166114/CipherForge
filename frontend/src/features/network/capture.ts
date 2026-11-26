import type { NetworkInterface, NetworkStatus } from "../../types/network";
import { isCaptureActive } from "./labels";
import { describeErrorCode, NETWORK_GUIDE } from "./messages";

export interface CaptureNotice {
  tone: "info" | "warn" | "bad";
  title: string;
  body: string;
}

function stateNotice(status: NetworkStatus): CaptureNotice | null {
  switch (status.state) {
    case "permission_denied":
      return {
        tone: "bad",
        title: "The operating system refused packet capture",
        body: `The operating system refused packet capture for the account that runs the CipherForge API. The privileges capture needs differ by platform, so follow the steps for yours in ${NETWORK_GUIDE}. Analysing a saved capture file does not need them.`,
      };
    case "not_configured":
      return {
        tone: "warn",
        title: "Live capture is not available",
        body: "No packet-capture library was detected on the server: Npcap on Windows, or libpcap on Linux and macOS. Install it and restart the API to capture live. Analysing a saved PCAP file may still work.",
      };
    case "failed":
      return {
        tone: "bad",
        title: "The last capture failed",
        body:
          status.message ??
          describeErrorCode(status.error_code)?.message ??
          "Packet capture stopped because of an error. The server log has the details.",
      };
    case "stopped":
      return {
        tone: "info",
        title: "Capture stopped",
        body: "The capture ended. Its results are kept below, and you can start a new capture.",
      };
    default:
      return null;
  }
}

/**
 * What to tell the analyst about live capture, beyond the state badge itself. Empty when the
 * badge says it all: ready, or a capture that is under way.
 */
export function captureNotices(status: NetworkStatus): CaptureNotice[] {
  const notices: CaptureNotice[] = [];
  const state = stateNotice(status);
  if (state !== null) notices.push(state);
  if (status.busy) {
    notices.push({
      tone: "warn",
      title: "Another capture is running",
      body: "Only one live capture can run at a time, and someone else's is using it. Start is available again when it ends. You can still analyse a PCAP file.",
    });
  }
  return notices;
}

export interface Availability {
  allowed: boolean;
  /** Why not, in a sentence, when it is not allowed. */
  reason: string | null;
}

export function startAvailability(
  status: NetworkStatus,
  interfaceId: string | null,
  interfaceCount: number,
): Availability {
  if (!status.backend.available || status.state === "not_configured") {
    return { allowed: false, reason: "Live capture is not available on this server." };
  }
  if (isCaptureActive(status.state)) {
    return { allowed: false, reason: "A capture is already running. Stop it to start another." };
  }
  if (status.busy) {
    return { allowed: false, reason: "Another capture holds the single capture slot." };
  }
  if (interfaceCount === 0) {
    return { allowed: false, reason: "There is no interface to capture on." };
  }
  if (interfaceId === null || interfaceId === "") {
    return { allowed: false, reason: "Choose an interface first." };
  }
  return { allowed: true, reason: null };
}

export function stopAvailability(status: NetworkStatus): Availability {
  if (status.state === "running" || status.state === "starting") {
    return { allowed: true, reason: null };
  }
  if (status.state === "stopping") return { allowed: false, reason: "The capture is already stopping." };
  return { allowed: false, reason: "No capture of yours is running." };
}

/** "eth0 - Ethernet adapter": the name, and the description when it adds anything. */
export function interfaceLabel(entry: Pick<NetworkInterface, "name" | "description">): string {
  const description = entry.description.trim();
  return description === "" || description === entry.name ? entry.name : `${entry.name} - ${description}`;
}

/**
 * The interface a running capture uses, as an `id` of the list. The status names it, and a name
 * can differ from the id on some platforms, so both are tried.
 */
export function activeInterfaceId(
  status: Pick<NetworkStatus, "interface">,
  interfaces: readonly NetworkInterface[],
): string | null {
  if (status.interface === null) return null;
  const match = interfaces.find((entry) => entry.id === status.interface || entry.name === status.interface);
  return match?.id ?? null;
}
