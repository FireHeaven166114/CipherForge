import type {
  ActivityList,
  FileFeatureStatus,
  FileList,
  Share,
  ShareCreated,
  ShareRequest,
  StoredFile,
  StoredFileDetail,
} from "../types/files";
import { request, requestNoContent, uploadFile } from "./apiClient";
import {
  isActivityList,
  isFileFeatureStatus,
  isFileList,
  isShare,
  isShareCreated,
  isStoredFile,
  isStoredFileDetail,
} from "./filesGuards";

const BASE = "/api/v1/files";

export function getFileStatus(signal?: AbortSignal): Promise<FileFeatureStatus> {
  return request(`${BASE}/status`, { signal, guard: isFileFeatureStatus });
}

/**
 * Encrypts and stores a file. The server keeps only the ciphertext, and the key that protects it
 * never reaches this app.
 */
export function uploadStoredFile(file: File, signal?: AbortSignal): Promise<StoredFile> {
  return uploadFile(BASE, file, { fileName: file.name, signal, guard: isStoredFile });
}

export function listFiles(
  query: { limit?: number; offset?: number } = {},
  signal?: AbortSignal,
): Promise<FileList> {
  const params = new URLSearchParams();
  if (query.limit !== undefined) params.set("limit", String(query.limit));
  if (query.offset !== undefined) params.set("offset", String(query.offset));
  const search = params.toString();
  return request(`${BASE}${search ? `?${search}` : ""}`, { signal, guard: isFileList });
}

export function getStoredFile(fileId: string, signal?: AbortSignal): Promise<StoredFileDetail> {
  return request(`${BASE}/${encodeURIComponent(fileId)}`, { signal, guard: isStoredFileDetail });
}

/** Removes the encrypted file and its links. The audit trail keeps its record of both. */
export function deleteStoredFile(fileId: string, signal?: AbortSignal): Promise<void> {
  return requestNoContent(`${BASE}/${encodeURIComponent(fileId)}`, { signal });
}

export function createShare(
  fileId: string,
  options: ShareRequest,
  signal?: AbortSignal,
): Promise<ShareCreated> {
  return request(`${BASE}/${encodeURIComponent(fileId)}/shares`, {
    method: "POST",
    body: options,
    signal,
    // Choosing a password runs a deliberately slow key derivation on the server.
    timeoutMs: 30_000,
    guard: isShareCreated,
  });
}

export function revokeShare(
  fileId: string,
  shareId: string,
  signal?: AbortSignal,
): Promise<Share> {
  return request(
    `${BASE}/${encodeURIComponent(fileId)}/shares/${encodeURIComponent(shareId)}/revoke`,
    { method: "POST", signal, guard: isShare },
  );
}

export function getFileActivity(fileId: string, signal?: AbortSignal): Promise<ActivityList> {
  return request(`${BASE}/${encodeURIComponent(fileId)}/activity`, {
    signal,
    guard: isActivityList,
  });
}
