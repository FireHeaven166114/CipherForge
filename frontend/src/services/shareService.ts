import type { PublicShareInfo } from "../types/files";
import { downloadFile, request, type DownloadedFile } from "./apiClient";
import { isPublicShareInfo } from "./filesGuards";

// A share link works for anyone who holds it, so nothing here ever sends the signed-in analyst's
// token: `authenticated: false` keeps the bearer header off these requests.

function sharePath(token: string): string {
  return `/api/v1/shares/${encodeURIComponent(token)}`;
}

/** What the link offers. This does not use up a download. */
export function getShareInfo(token: string, signal?: AbortSignal): Promise<PublicShareInfo> {
  return request(sharePath(token), { signal, authenticated: false, guard: isPublicShareInfo });
}

/**
 * Downloads the decrypted file. The password, when the link has one, goes in the request body and
 * never in the address, where it would end up in logs and in the browser's history.
 */
export function downloadShare(
  token: string,
  password: string | null,
  signal?: AbortSignal,
): Promise<DownloadedFile> {
  return downloadFile(`${sharePath(token)}/download`, {
    method: "POST",
    body: password === null ? undefined : { password },
    signal,
    authenticated: false,
  });
}
