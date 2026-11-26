import type { ApiError } from "../../services/apiClient";

/** Everything that can go wrong on the public page, grouped by what the recipient can do about it. */
export type ShareFailureKind =
  | "not_found"
  | "expired"
  | "revoked"
  | "limit_reached"
  | "integrity"
  | "unavailable"
  | "busy"
  | "wrong_password"
  | "password_required"
  | "rate_limited"
  | "network"
  | "unknown";

export interface ShareFailure {
  kind: ShareFailureKind;
  /** How long the server asked the recipient to wait; only sent with a rate limit or a busy server. */
  waitSeconds: number | undefined;
  /** The request's correlation id, which the sender can pass on to an administrator. */
  reference: string | undefined;
}

export interface ShareStateText {
  title: string;
  message: string;
  /** Nothing the recipient does can change the outcome, so the whole card is replaced. */
  terminal: boolean;
  /** Whether trying the same request again can help. */
  retry: boolean;
}

// The public page never names server settings or internals: a stranger with a link has no use for
// them, and no business knowing them.
export const SHARE_STATE_TEXT: Record<ShareFailureKind, ShareStateText> = {
  not_found: {
    title: "This link does not work",
    message:
      "The link may have been copied incompletely, or it no longer exists. Ask the person who sent it for a new link.",
    terminal: true,
    retry: false,
  },
  expired: {
    title: "This link has expired",
    message:
      "A shared link stops working at the time its sender chose. Ask the sender for a new link if you still need the file.",
    terminal: true,
    retry: false,
  },
  revoked: {
    title: "This link has been revoked",
    message:
      "The sender turned this link off, so the file can no longer be downloaded with it. Ask them for a new link if you still need it.",
    terminal: true,
    retry: false,
  },
  limit_reached: {
    title: "This link has reached its download limit",
    message:
      "The sender allowed a limited number of downloads and they have all been used. Ask the sender for a new link.",
    terminal: true,
    retry: false,
  },
  integrity: {
    title: "This file could not be verified and was not released",
    message:
      "The stored copy did not pass its integrity check, so nothing was sent to you. Tell the person who shared it.",
    terminal: true,
    retry: false,
  },
  unavailable: {
    title: "Sharing is not available right now",
    message:
      "The server cannot open shared files at the moment. Try again later, or tell the person who sent you the link.",
    terminal: false,
    retry: true,
  },
  busy: {
    title: "The server is busy",
    message: "Many files are being opened at once. Wait a moment and try again.",
    terminal: false,
    retry: true,
  },
  wrong_password: {
    title: "That password is not correct",
    message: "Check the password you were given and try again.",
    terminal: false,
    retry: true,
  },
  password_required: {
    title: "A password is needed",
    message: "This file is protected by a password. Enter it to download the file.",
    terminal: false,
    retry: true,
  },
  rate_limited: {
    title: "Too many attempts",
    message: "Too many attempts were made from your connection. Wait before trying again.",
    terminal: false,
    retry: true,
  },
  network: {
    title: "Could not reach CipherForge",
    message: "Check your internet connection, then try again.",
    terminal: false,
    retry: true,
  },
  unknown: {
    title: "Something went wrong",
    message: "The request did not work. Try again, and if it keeps failing tell the person who sent you the link.",
    terminal: false,
    retry: true,
  },
};

const KIND_BY_CODE = new Map<string, ShareFailureKind>([
  ["share_not_found", "not_found"],
  ["share_expired", "expired"],
  ["share_revoked", "revoked"],
  ["share_limit_reached", "limit_reached"],
  ["file_unavailable", "integrity"],
  ["password_required", "password_required"],
  ["invalid_password", "wrong_password"],
  ["rate_limited", "rate_limited"],
  ["too_many_attempts", "rate_limited"],
  ["feature_not_configured", "unavailable"],
  ["encryption_key_mismatch", "unavailable"],
  ["storage_unavailable", "unavailable"],
  ["service_busy", "busy"],
  ["network_error", "network"],
  ["timeout", "network"],
]);

function kindFromStatus(status: number): ShareFailureKind {
  if (status === 404 || status === 410) return "not_found";
  if (status === 429) return "rate_limited";
  if (status === 502 || status === 503 || status === 504) return "unavailable";
  return "unknown";
}

/** Sorts an API failure into one of the states the page knows how to word. */
export function classifyShareError(error: ApiError): ShareFailure {
  const kind = KIND_BY_CODE.get(error.code) ?? kindFromStatus(error.status);
  return {
    kind,
    waitSeconds: kind === "rate_limited" || kind === "busy" ? error.retryAfterSeconds : undefined,
    reference: error.correlationId,
  };
}
