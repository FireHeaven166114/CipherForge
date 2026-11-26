import { sanitizeFileName } from "./disposition";

/**
 * How long the object URL outlives the click. The browser reads the blob as soon as the download
 * starts, but some browsers do so asynchronously, and revoking at once would cancel them.
 */
export const REVOKE_DELAY_MS = 10_000;

/** Offers a blob to the person as a download, under a name made safe to save as. */
export function saveBlob(blob: Blob, fileName: string): void {
  const url = URL.createObjectURL(blob);
  try {
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = sanitizeFileName(fileName);
    anchor.rel = "noopener";
    anchor.hidden = true;
    document.body.append(anchor);
    try {
      anchor.click();
    } finally {
      anchor.remove();
    }
  } finally {
    window.setTimeout(() => URL.revokeObjectURL(url), REVOKE_DELAY_MS);
  }
}
