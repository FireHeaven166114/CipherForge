/**
 * The address a recipient opens: the page's own origin plus the path the API returned. The origin
 * is always this page's, so a path from the API can never point somewhere else.
 */
export function buildShareLink(path: string, origin: string = window.location.origin): string {
  return `${origin}${path.startsWith("/") ? path : `/${path}`}`;
}

/** Copies what is selected in `source` the old way, for pages where the clipboard API is not offered. */
function copySelection(source: HTMLInputElement | null): boolean {
  if (source === null) return false;
  source.focus();
  source.select();
  if (typeof document.execCommand !== "function") return false;
  try {
    return document.execCommand("copy");
  } catch {
    return false;
  }
}

/**
 * Puts `text` on the clipboard. The clipboard API needs a secure page and permission, so when it
 * is missing or refuses, the text in `source` is selected and copied the old way. When that fails
 * too the text stays selected, ready for the person to copy it themselves. Resolves to whether the
 * clipboard now holds the text.
 */
export async function copyText(text: string, source: HTMLInputElement | null): Promise<boolean> {
  if (typeof navigator !== "undefined" && typeof navigator.clipboard?.writeText === "function") {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // Refused or unavailable: fall back to selecting the text.
    }
  }
  return copySelection(source);
}
