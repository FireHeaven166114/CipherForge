import type { ApiError } from "../../services/apiClient";
import { formatWait } from "../intel/format";
import { formatBytes } from "../units";

/** The server setting that switches encrypted files on. It is named in text only, never read. */
export const MASTER_KEY_SETTING = "CIPHERFORGE_MASTER_KEY";

export interface ErrorContext {
  /** The server's size limit, so an answer that a file is too large can say what the limit is. */
  maxFileSizeBytes?: number;
}

function tooLarge({ maxFileSizeBytes }: ErrorContext): string {
  return maxFileSizeBytes === undefined
    ? "That file is larger than this server accepts. Choose a smaller file."
    : `That file is larger than the ${formatBytes(maxFileSizeBytes)} limit. Choose a smaller file.`;
}

function tryAgain(error: ApiError): string {
  return error.retryAfterSeconds === undefined
    ? "Try again shortly."
    : `Try again in ${formatWait(error.retryAfterSeconds)}.`;
}

/**
 * Turns a failure of the console's own file calls (upload, share, revoke, delete) into a sentence
 * that says what happened and what to do. The API's codes decide the wording; its message is only
 * the last resort, because it is written for a log, not for the person who pressed the button.
 */
export function describeFileError(error: ApiError, context: ErrorContext = {}): string {
  switch (error.code) {
    case "file_too_large":
    case "request_too_large":
      return tooLarge(context);
    case "empty_file":
      return "That file is empty, so there is nothing to encrypt.";
    case "invalid_filename":
      return "That file name cannot be used. Rename the file and try again.";
    case "unsupported_media_type":
      return "The server refused this kind of upload. Reload the page and try again.";
    case "invalid_content_length":
    case "upload_interrupted":
      return "The upload did not finish, so nothing was stored. Try again.";
    case "feature_not_configured":
      return `Encrypted files are not set up on this server. An administrator must set ${MASTER_KEY_SETTING}.`;
    case "encryption_key_mismatch":
      return `The server's master key does not match the one that protects these files, so nothing was changed. An administrator must check ${MASTER_KEY_SETTING}.`;
    case "file_not_found":
      return "This file no longer exists. It may have been deleted.";
    case "share_not_found":
      return "This link no longer exists.";
    case "file_unavailable":
      return "This file failed its integrity check, so it cannot be shared.";
    case "rate_limited":
      return `Too many requests. ${tryAgain(error)}`;
    case "service_busy":
      return `The server is busy encrypting other files. ${tryAgain(error)}`;
    case "storage_unavailable":
      return "The server could not reach its encrypted storage. Try again shortly.";
    case "validation_error":
      return "The server did not accept those values. Check them and try again.";
    case "network_error":
      return "Could not reach the CipherForge API. Check your connection and try again.";
    case "timeout":
      return "The request took too long and was stopped. Check the list before trying again, in case it went through.";
  }

  switch (error.status) {
    case 401:
      return "You are not signed in, so the API refused this.";
    case 403:
      return "Your account is not allowed to do this.";
    case 413:
      return tooLarge(context);
    case 429:
      return `Too many requests. ${tryAgain(error)}`;
    case 422:
      return "The server did not accept those values. Check them and try again.";
  }

  if (error.status >= 500) return "The API reported an error. Try again shortly.";
  return error.message === "" ? "The request failed. Try again." : error.message;
}
