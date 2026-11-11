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
