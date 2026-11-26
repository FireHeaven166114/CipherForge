import { formatBytes } from "../units";

/** What the file picker offers: the three extensions the server takes. */
export const FILE_ACCEPT = ".pcap,.pcapng,.cap";

const EXTENSIONS = [".pcap", ".pcapng", ".cap"] as const;
const MAX_ENCODED_NAME = 1024;
const BYTES_PER_MB = 1024 * 1024;

export type FileCheck = { ok: true } | { ok: false; reason: string };

/** The largest upload, in bytes, for a limit in megabytes (the server counts in steps of 1024). */
export function uploadLimitBytes(maxUploadMb: number): number {
  return maxUploadMb * BYTES_PER_MB;
}

/**
 * A quick look at a file before it is sent, so an obvious mistake does not cost an upload. It only
 * saves time: the server checks the name, the size and the content again, and has the last word.
 */
export function checkCaptureFile(file: Pick<File, "name" | "size">, maxUploadMb: number): FileCheck {
  const lower = file.name.toLowerCase();
  const extension = EXTENSIONS.find((candidate) => lower.endsWith(candidate));
  if (extension === undefined) {
    return {
      ok: false,
      reason: `"${file.name}" is not a capture file. Choose a file that ends in .pcap, .pcapng or .cap.`,
    };
  }
  if (lower === extension) {
    return {
      ok: false,
      reason: `The file has no name before "${extension}". Rename it and choose it again.`,
    };
  }
  if (encodeURIComponent(file.name).length > MAX_ENCODED_NAME) {
    return { ok: false, reason: "The file name is too long. Rename the file and choose it again." };
  }
  if (file.size <= 0) {
    return { ok: false, reason: `"${file.name}" is empty, so there is nothing to analyse.` };
  }
  if (maxUploadMb > 0 && file.size > uploadLimitBytes(maxUploadMb)) {
    return {
      ok: false,
      reason: `"${file.name}" is ${formatBytes(file.size)}, over the ${maxUploadMb} MB limit.`,
    };
  }
  return { ok: true };
}
