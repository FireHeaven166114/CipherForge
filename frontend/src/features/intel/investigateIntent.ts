import { MAX_INDICATOR_LENGTH } from "./limits";

/** What the Investigate page reads from the router when it is opened from the command palette. */
export interface InvestigateIntent {
  indicator: string;
  /** Start the lookup straight away. The page sets this to false once it has acted on it. */
  autorun: boolean;
  /** Tells one request from the next, so asking about the same indicator twice runs twice. */
  nonce: string;
}

let sequence = 0;

/**
 * An intent that asks the Investigate page to look something up. It travels in router state, not
 * in the address, so following a link can never start a lookup. The time is part of the nonce so
 * that a request made after a page reload is never mistaken for one made before it.
 */
export function createIntent(indicator: string): InvestigateIntent {
  sequence += 1;
  return { indicator, autorun: true, nonce: `${Date.now()}.${sequence}` };
}

/** Reads router state back into an intent, or null when it is anything else (state is untyped). */
export function readIntent(state: unknown): InvestigateIntent | null {
  if (typeof state !== "object" || state === null) return null;
  const { indicator, autorun, nonce } = state as Record<string, unknown>;
  if (typeof indicator !== "string" || typeof autorun !== "boolean" || typeof nonce !== "string") {
    return null;
  }
  const trimmed = indicator.trim();
  if (trimmed === "" || trimmed.length > MAX_INDICATOR_LENGTH) return null;
  return { indicator: trimmed, autorun, nonce };
}
