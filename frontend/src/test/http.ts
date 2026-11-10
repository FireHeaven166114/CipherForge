import { vi } from "vitest";

export function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json" },
    ...init,
  });
}

type Handler = (url: string, init: RequestInit | undefined) => Response | Promise<Response>;

/** Replaces the global fetch for one test; `unstubGlobals` in vite.config.ts restores it. */
export function stubFetch(handler: Handler) {
  const mock = vi.fn((input: RequestInfo | URL, init?: RequestInit) =>
    Promise.resolve(handler(String(input), init)),
  );
  vi.stubGlobal("fetch", mock);
  return mock;
}

/** A fetch that never answers on its own and rejects with the abort reason when cancelled. */
export function hangingFetch(): Handler {
  return (_url, init) =>
    new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener("abort", () => reject(init.signal?.reason));
    });
}
