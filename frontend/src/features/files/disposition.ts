/** What a download is called when the response does not say, or says something unusable. */
export const FALLBACK_FILE_NAME = "download";

/** The longest name kept, in characters (code points); the server's own limit for stored names. */
export const MAX_FILE_NAME_LENGTH = 255;

const MAX_EXTENSION_LENGTH = 16;

// Device names that Windows will not use as a file name, with or without an extension.
const RESERVED_NAME = /^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?$/i;

// A surrogate half with no partner: it cannot be encoded as UTF-8 and breaks naive string handling.
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;

function truncate(name: string): string {
  const characters = Array.from(name);
  if (characters.length <= MAX_FILE_NAME_LENGTH) return name;

  const dot = name.lastIndexOf(".");
  const extension = dot > 0 ? Array.from(name.slice(dot)) : [];
  if (extension.length > 1 && extension.length <= MAX_EXTENSION_LENGTH) {
    const stem = Array.from(name.slice(0, dot));
    return stem.slice(0, MAX_FILE_NAME_LENGTH - extension.length).join("") + extension.join("");
  }
  return characters.slice(0, MAX_FILE_NAME_LENGTH).join("");
}

/**
 * Makes a name safe to hand to the browser's "save as": one path component, no control or invisible
 * formatting characters (bidi overrides included), nothing Windows refuses, a bounded length.
 * Returns null when nothing usable is left, so a caller can try a different candidate.
 */
export function cleanFileName(name: string): string | null {
  const flattened = name
    .replace(LONE_SURROGATE, "_")
    .normalize("NFC")
    .replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, "");

  const components = flattened.split(/[\\/]/).filter((part) => part.trim() !== "");
  const last = components.at(-1);
  if (last === undefined) return null;

  const safe = last
    .replace(/[<>:"|?*]/g, "_")
    .replace(/^[\s.]+/, "")
    .replace(/[\s.]+$/, "");
  if (safe === "") return null;

  const shortened = truncate(RESERVED_NAME.test(safe) ? `_${safe}` : safe).replace(/[\s.]+$/, "");
  return shortened === "" ? null : shortened;
}

/** `cleanFileName`, or the neutral fallback when nothing is left of the name. */
export function sanitizeFileName(name: string): string {
  return cleanFileName(name) ?? FALLBACK_FILE_NAME;
}

/** Splits on semicolons that are not inside a quoted string, keeping each quoted pair intact. */
function splitParameters(header: string): string[] {
  const parts: string[] = [];
  let current = "";
  let quoted = false;
  for (let index = 0; index < header.length; index += 1) {
    const char = header.charAt(index);
    if (quoted && char === "\\") {
      current += char + header.charAt(index + 1);
      index += 1;
    } else if (char === '"') {
      quoted = !quoted;
      current += char;
    } else if (char === ";" && !quoted) {
      parts.push(current);
      current = "";
    } else {
      current += char;
    }
  }
  parts.push(current);
  return parts;
}

function unquote(raw: string): string {
  if (raw.length >= 2 && raw.startsWith('"') && raw.endsWith('"')) {
    return raw.slice(1, -1).replace(/\\(.)/gs, "$1");
  }
  return raw;
}

/** RFC 5987: `UTF-8''%E2%82%AC%20rates`. Null when the charset is unknown or the bytes are invalid. */
function decodeExtendedValue(raw: string): string | null {
  const match = /^([^']*)'[^']*'(.*)$/s.exec(raw);
  if (match === null) return null;

  const charset = (match[1] ?? "").toLowerCase();
  const encoded = match[2] ?? "";
  try {
    if (charset === "utf-8") return decodeURIComponent(encoded);
    if (charset === "iso-8859-1") {
      return encoded.replace(/%([0-9a-f]{2})/gi, (_, hex: string) => String.fromCharCode(Number.parseInt(hex, 16)));
    }
  } catch {
    return null;
  }
  return null;
}

/**
 * The file name a response asks for. The extended `filename*` wins over `filename`, because the
 * server sends the real name there and only an ASCII stand-in in the other; whatever is chosen is
 * made safe to save under, and a response with no usable name is called "download".
 */
export function fileNameFromDisposition(header: string | null): string {
  if (header === null) return FALLBACK_FILE_NAME;

  let extended: string | null = null;
  let plain: string | null = null;
  for (const part of splitParameters(header).slice(1)) {
    const equals = part.indexOf("=");
    if (equals === -1) continue;
    const name = part.slice(0, equals).trim().toLowerCase();
    const value = part.slice(equals + 1).trim();
    if (name === "filename*" && extended === null) extended = decodeExtendedValue(value);
    if (name === "filename" && plain === null) plain = unquote(value);
  }

  for (const candidate of [extended, plain]) {
    if (candidate === null) continue;
    const cleaned = cleanFileName(candidate);
    if (cleaned !== null) return cleaned;
  }
  return FALLBACK_FILE_NAME;
}
