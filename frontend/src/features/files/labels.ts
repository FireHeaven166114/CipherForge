import type { Tone } from "../../components/StatusBadge";
import type { FileState, ShareStatus, StoredFile } from "../../types/files";
import { plural } from "../intel/format";

export interface Meta {
  label: string;
  tone: Tone;
}

export const SHARE_STATUS_META: Record<ShareStatus, Meta> = {
  active: { label: "Active", tone: "ok" },
  expired: { label: "Expired", tone: "warn" },
  revoked: { label: "Revoked", tone: "bad" },
  exhausted: { label: "Limit reached", tone: "warn" },
};

export const FILE_STATE_META: Record<FileState, Meta> = {
  active: { label: "Ready", tone: "ok" },
  corrupt: { label: "Integrity problem", tone: "bad" },
};

// Maps, not objects: an action or reason is text from the API, and "constructor" must not find
// something on Object.prototype.
const ACTION_LABELS = new Map<string, string>([
  ["FILE_CREATE", "File uploaded"],
  ["SHARE_CREATE", "Link created"],
  ["SHARE_DOWNLOAD", "File downloaded"],
  ["SHARE_DOWNLOAD_REJECTED", "Download refused"],
  ["SHARE_PASSWORD_FAILED", "Wrong password"],
  ["SHARE_EXPIRED", "Expired link opened"],
  ["SHARE_REVOKE", "Link revoked"],
  ["SHARE_LIMIT_REACHED", "Download limit reached"],
  ["FILE_INTEGRITY_FAILED", "Integrity check failed"],
  ["FILE_DELETE", "File deleted"],
]);

const RESULT_META = new Map<string, Meta>([
  ["success", { label: "Success", tone: "ok" }],
  ["rejected", { label: "Rejected", tone: "warn" }],
  ["partial", { label: "Partial", tone: "warn" }],
  ["failed", { label: "Failed", tone: "bad" }],
]);

const REASON_LABELS = new Map<string, string>([
  ["revoked", "The link had been revoked"],
  ["expired", "The link had expired"],
  ["limit_reached", "The download limit was used up"],
  ["file_unavailable", "The file could not be read or verified"],
  ["password_required", "A password was needed and none was given"],
  ["invalid_password", "The password was wrong"],
  ["key_mismatch", "The server's master key did not match"],
  ["wrapped_key_invalid", "The file's key could not be unwrapped"],
  ["authentication_failed", "The encrypted data failed its authenticity check"],
  ["blob_invalid", "The stored data was missing or malformed"],
]);

/** What an audit action is called on screen; an action this console does not know is shown as sent. */
export function actionLabel(action: string): string {
  return ACTION_LABELS.get(action) ?? action;
}

export function resultMeta(result: string): Meta {
  return RESULT_META.get(result) ?? { label: result === "" ? "Unknown" : result, tone: "neutral" };
}

/** Null when the entry has no reason, so the table can show a dash. */
export function reasonLabel(reason: string | null): string | null {
  if (reason === null || reason === "") return null;
  return REASON_LABELS.get(reason) ?? reason;
}

/** Enough of an id to tell links apart in a list; the full id is never needed on screen. */
export function shortId(id: string): string {
  return id.slice(0, 8);
}

/** "2 active of 3 links", or "No links" for a file nobody has been given. */
export function describeLinks(file: Pick<StoredFile, "share_count" | "active_share_count">): string {
  if (file.share_count === 0) return "No links";
  return `${file.active_share_count} active of ${plural(file.share_count, "link")}`;
}
