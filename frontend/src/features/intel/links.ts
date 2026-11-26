// Links to external sites are built from a fixed base and an identifier that matches a strict
// pattern. Provider data is community-supplied, so it never chooses where a link points.

const PULSE_ID = /^[0-9a-f]{24}$/i;
const ATTACK_ID = /^T\d{4}(?:\.\d{3})?$/;

export function otxPulseUrl(id: unknown): string | null {
  return typeof id === "string" && PULSE_ID.test(id)
    ? `https://otx.alienvault.com/pulse/${id.toLowerCase()}`
    : null;
}

/** MITRE ATT&CK lists sub-techniques as T1059/001, not T1059.001. */
export function attackTechniqueUrl(id: unknown): string | null {
  return typeof id === "string" && ATTACK_ID.test(id)
    ? `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`
    : null;
}

const VIRUSTOTAL_LINK =
  /^https:\/\/www\.virustotal\.com\/gui\/(ip-address|domain|url|file)\/([A-Za-z0-9._:%-]{1,256})$/;

/**
 * VirusTotal's page for the indicator. The API sends a ready-made link, but only one of this exact
 * shape is accepted and it is rebuilt from its two parts, so nothing else can ride along.
 */
export function virusTotalUrl(link: unknown): string | null {
  const match = typeof link === "string" ? VIRUSTOTAL_LINK.exec(link) : null;
  return match ? `https://www.virustotal.com/gui/${match[1]}/${match[2]}` : null;
}

const THREATFOX_ID = /^\d{1,12}$/;

/** ThreatFox's page for one of its IOC records, from the numeric id the API reports. */
export function threatFoxIocUrl(id: unknown): string | null {
  return typeof id === "string" && THREATFOX_ID.test(id) ? `https://threatfox.abuse.ch/ioc/${id}/` : null;
}

const MALPEDIA_LINK =
  /^https:\/\/malpedia\.caad\.fkie\.fraunhofer\.de\/(details|actor)\/([a-z0-9_.-]{1,96})$/;

/** The Malpedia entry for a malware family or actor, when the address has exactly that shape. */
export function malpediaUrl(link: unknown): string | null {
  const match = typeof link === "string" ? MALPEDIA_LINK.exec(link) : null;
  return match ? `https://malpedia.caad.fkie.fraunhofer.de/${match[1]}/${match[2]}` : null;
}

/**
 * A reporter-supplied address, written so that it cannot be followed by accident. Reporters are
 * strangers, and the address may well point at the malware itself, so it is shown but never linked.
 */
export function defang(address: string): string {
  return address.replace(/^http/i, "hxxp");
}
