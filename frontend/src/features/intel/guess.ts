import type { IndicatorType } from "../../types/intel";

const IPV4_OCTET = "(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)";
const IPV4 = new RegExp(`^${IPV4_OCTET}(?:\\.${IPV4_OCTET}){3}$`);
const MD5 = /^[a-f0-9]{32}$/i;
const SHA1 = /^[a-f0-9]{40}$/i;
const SHA256 = /^[a-f0-9]{64}$/i;
const DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/i;

function parses(text: string): URL | null {
  try {
    return new URL(text);
  } catch {
    return null;
  }
}

function isIpv6(text: string): boolean {
  if (!/^[0-9a-f:.]+$/i.test(text) || text.split(":").length < 3) return false;
  return parses(`http://[${text}]/`) !== null;
}

function isWebUrl(text: string): boolean {
  const url = parses(text);
  return url !== null && (url.protocol === "http:" || url.protocol === "https:") && url.hostname !== "";
}

/**
 * What a piece of text looks like, so the scanner can show it while the analyst types. This is
 * a hint only: the API decides what it accepts, and says why when it refuses something.
 */
export function guessIndicatorType(text: string): IndicatorType | null {
  const value = text.trim();
  if (value === "") return null;
  if (IPV4.test(value)) return "ipv4";
  if (SHA256.test(value)) return "sha256";
  if (SHA1.test(value)) return "sha1";
  if (MD5.test(value)) return "md5";
  if (isIpv6(value)) return "ipv6";
  if (/^https?:\/\//i.test(value)) return isWebUrl(value) ? "url" : null;
  return DOMAIN.test(value) ? "domain" : null;
}
