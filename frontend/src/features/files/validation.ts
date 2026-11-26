import type { FileFeatureStatus, ShareRequest } from "../../types/files";
import { formatBytes } from "../units";

export interface ShareFormValues {
  expiresInHours: string;
  maxDownloads: string;
  password: string;
}

export type ShareField = keyof ShareFormValues;
export type ShareFormErrors = Partial<Record<ShareField, string>>;

export interface ShareValidation {
  errors: ShareFormErrors;
  /** The body to send; null while any field is invalid. */
  request: ShareRequest | null;
}

/** The longest `X-File-Name` the API accepts, counted after percent-encoding. */
export const MAX_NAME_HEADER_LENGTH = 1024;

const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/** What the form starts with, and what it goes back to after a link is made. */
export function defaultShareValues(status: FileFeatureStatus): ShareFormValues {
  return {
    expiresInHours: String(Math.min(status.default_share_expiry_hours, status.max_share_expiry_hours)),
    maxDownloads: "1",
    password: "",
  };
}

/** A whole number from `min` to `max`, or null for anything else (empty, decimal, signed, huge). */
function wholeNumber(text: string, min: number, max: number): number | null {
  const trimmed = text.trim();
  if (!/^\d{1,9}$/.test(trimmed)) return null;
  const value = Number(trimmed);
  return value >= min && value <= max ? value : null;
}

/** Characters as a person counts them: "é" typed as two code units is still one. */
export function passwordLength(password: string): number {
  return Array.from(password).length;
}

export function validatePassword(password: string, status: FileFeatureStatus): string | null {
  if (password === "") return null;
  if (LONE_SURROGATE.test(password)) {
    return "The password contains a character that cannot be sent. Remove it and try again.";
  }
  const length = passwordLength(password);
  if (length < status.min_password_length) {
    return `Use at least ${status.min_password_length} characters, or leave the password empty for no password.`;
  }
  if (length > status.max_password_length) {
    return `Use at most ${status.max_password_length} characters.`;
  }
  return null;
}

/**
 * Checks the share form against the server's limits and builds the request body. The server stays
 * the authority; this only spares a round trip and says which field is wrong. The password is sent
 * only when one was typed, because an empty string is not "no password" to the API.
 */
export function validateShareForm(values: ShareFormValues, status: FileFeatureStatus): ShareValidation {
  const errors: ShareFormErrors = {};

  const hours = wholeNumber(values.expiresInHours, 1, status.max_share_expiry_hours);
  if (hours === null) {
    errors.expiresInHours = `Enter a whole number of hours from 1 to ${status.max_share_expiry_hours}.`;
  }

  const downloads = wholeNumber(values.maxDownloads, 1, status.max_share_downloads);
  if (downloads === null) {
    errors.maxDownloads = `Enter a whole number of downloads from 1 to ${status.max_share_downloads}.`;
  }

  const passwordError = validatePassword(values.password, status);
  if (passwordError !== null) errors.password = passwordError;

  if (hours === null || downloads === null || passwordError !== null) return { errors, request: null };

  const request: ShareRequest = { expires_in_hours: hours, max_downloads: downloads };
  if (values.password !== "") request.password = values.password;
  return { errors, request };
}

/** Why a file cannot be uploaded, or null when it can. The server is still asked, and still decides. */
export function validateUpload(file: Pick<File, "name" | "size">, maxBytes: number | undefined): string | null {
  if (file.size === 0) return "That file is empty, so there is nothing to encrypt.";
  if (maxBytes !== undefined && file.size > maxBytes) {
    return `That file is ${formatBytes(file.size)}, which is over the ${formatBytes(maxBytes)} limit.`;
  }
  if (file.name.trim() === "") return "That file has no name. Rename it and try again.";

  try {
    if (encodeURIComponent(file.name).length > MAX_NAME_HEADER_LENGTH) {
      return "That file name is too long. Rename the file with a shorter name and try again.";
    }
  } catch {
    return "That file name contains a character that cannot be sent. Rename the file and try again.";
  }
  return null;
}
