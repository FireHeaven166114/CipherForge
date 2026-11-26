const SESSION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** The session id in a `?session=` link, or null when there is none or it is not a session id. */
export function parseSessionParam(value: string | null): string | null {
  return value !== null && SESSION_ID.test(value) ? value.toLowerCase() : null;
}

/**
 * Which session the page shows: the one the analyst picked or linked to, else the one of their
 * own live capture (running, or the last that ended), else none.
 */
export function resolveSessionId(requested: string | null, live: string | null): string | null {
  return requested ?? live;
}
