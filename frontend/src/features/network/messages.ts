import type { ApiError } from "../../services/apiClient";
import { formatWait } from "../intel/format";

/** A calm, specific replacement for an API failure: what happened, and what can be done. */
export interface MappedMessage {
  title: string;
  message: string;
}

export interface MessageContext {
  /** The upload limit this server announced, so "too large" can name it. */
  maxUploadMb?: number;
}

// Plain text on purpose: the guide is a file in the repository, not a page of this console.
export const NETWORK_GUIDE = "docs/network-monitoring.md";

const BY_CODE: Readonly<Record<string, MappedMessage>> = {
  capture_permission_denied: {
    title: "Packet capture not permitted",
    message: `The operating system refused packet capture for the account that runs the CipherForge API. The privileges capture needs differ by platform; see ${NETWORK_GUIDE}.`,
  },
  capture_backend_missing: {
    title: "No packet-capture library found",
    message:
      "No packet-capture library was found on the server. Install Npcap (Windows) or libpcap (Linux and macOS), then restart the API. Analysing a saved capture file may still work.",
  },
  interface_unavailable: {
    title: "Interface unavailable",
    message:
      "That network interface is not available. It may have been disconnected or disabled. Refresh the list and choose another interface.",
  },
  capture_failed: {
    title: "Capture stopped by an error",
    message: "Packet capture stopped because of an error. The server log has the details.",
  },
  interrupted: {
    title: "Session ended early",
    message: "The application stopped while this session was running, so it ended early.",
  },
  invalid_capture_file: {
    title: "Not a readable capture file",
    message:
      "That file is not a readable PCAP or PCAPNG capture, or it holds no complete packet. Nothing was kept from it.",
  },
  capture_truncated: {
    title: "Capture file cut short",
    message:
      "The capture file is cut short or damaged after some point. Everything before that point was analysed.",
  },
  analysis_timeout: {
    title: "Analysis timed out",
    message: "The analysis took too long and was stopped. The results so far are kept.",
  },
  analysis_failed: {
    title: "Analysis failed",
    message: "The capture file could not be analysed. The server log has the details.",
  },
  results_incomplete: {
    title: "Results may be incomplete",
    message:
      "Some results could not be stored because the database was unavailable, so the totals may be incomplete.",
  },
  interface_not_found: {
    title: "Interface not found",
    message: "That interface is no longer listed. Refresh the interface list and choose again.",
  },
  capture_already_running: {
    title: "A capture is already running",
    message:
      "Only one live capture can run at a time, and one is already running. Stop it, or wait until it ends, before starting another.",
  },
  capture_not_running: {
    title: "No capture to stop",
    message: "None of your live captures is running. It may have ended already.",
  },
  analysis_already_running: {
    title: "Another analysis is in progress",
    message:
      "A capture file is being analysed right now. Wait for it to finish, then upload your file again.",
  },
  session_not_found: {
    title: "Session not found",
    message: "That session no longer exists, or it belongs to another account.",
  },
  session_running: {
    title: "Session still running",
    message:
      "That session is still running. Stop the capture, or wait for the analysis to finish, before deleting it.",
  },
  alert_not_found: {
    title: "Alert not found",
    message: "That alert no longer exists. Its session may have been deleted.",
  },
  enrichment_disabled: {
    title: "External enrichment is switched off",
    message: "External enrichment is switched off on this server, so addresses cannot be looked up.",
  },
  address_not_public: {
    title: "Nothing to look up",
    message:
      "This alert involves no public address. Private addresses are never looked up or sent to a provider.",
  },
  invalid_filename: {
    title: "Invalid file name",
    message:
      "The server could not use that file name. Rename the file so it ends in .pcap, .pcapng or .cap, then upload it again.",
  },
  invalid_content_length: {
    title: "Upload size not valid",
    message: "The upload did not state its size correctly. Choose the file again and retry.",
  },
  upload_interrupted: {
    title: "Upload interrupted",
    message: "The upload stopped before the whole file arrived. Check the connection and try again.",
  },
  unsupported_media_type: {
    title: "Upload type not accepted",
    message:
      "The server accepts a capture only as a raw binary upload. Reload the page and try again. If it keeps happening, tell an administrator.",
  },
};

function fileTooLarge(context: MessageContext): MappedMessage {
  const limit = context.maxUploadMb === undefined ? "the" : `the ${context.maxUploadMb} MB`;
  return {
    title: "File too large",
    message: `The file is larger than ${limit} upload limit. Upload a smaller capture, or cut this one down first.`,
  };
}

function lookup(code: string): MappedMessage | null {
  return Object.hasOwn(BY_CODE, code) ? (BY_CODE[code] ?? null) : null;
}

/**
 * The calm wording for an API failure, or null when the API's own message is the best there is
 * (timeouts, outages and codes this console does not know). A code wins over a status, because
 * the same status can mean several things.
 */
export function describeNetworkError(
  error: ApiError,
  context: MessageContext = {},
): MappedMessage | null {
  if (error.code === "file_too_large") return fileTooLarge(context);
  const byCode = lookup(error.code);
  if (byCode !== null) return byCode;

  switch (error.status) {
    case 401:
      return {
        title: "Sign in needed",
        message:
          "You are not signed in, or your session has ended. Sign in with an account that has the security analyst role, then try again.",
      };
    case 403:
      return {
        title: "Security analyst role needed",
        message:
          "Network monitoring needs the security analyst role. Ask an administrator to grant it, or sign in with another account.",
      };
    case 413:
      return fileTooLarge(context);
    case 415:
      return lookup("unsupported_media_type");
    case 429:
      return {
        title: "Too many requests",
        message: `The server asked for a pause. Try again in ${
          error.retryAfterSeconds === undefined ? "a moment" : formatWait(error.retryAfterSeconds)
        }.`,
      };
    default:
      return null;
  }
}

/** The text to show for a failure: the calm wording when there is one, else the API's message. */
export function networkErrorMessage(error: ApiError, context: MessageContext = {}): string {
  return describeNetworkError(error, context)?.message ?? error.message;
}

/**
 * The same wording for a code that arrives inside data instead of an error: a session or the
 * capture status carries the reason it ended early. Null for no code, or one not known here.
 */
export function describeErrorCode(code: string | null | undefined): MappedMessage | null {
  return code === null || code === undefined ? null : lookup(code);
}
