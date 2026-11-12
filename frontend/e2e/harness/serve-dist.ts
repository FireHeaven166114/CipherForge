/**
 * A stand-in for the production nginx, used only by the end-to-end tests.
 *
 * It serves the real build from dist/ and forwards the same three paths nginx forwards to the
 * API. The security headers are read out of nginx.conf rather than copied, so the browser tests
 * always run under the policy that ships. Run it with `node e2e/harness/serve-dist.ts`.
 */
import { createReadStream, readFileSync, statSync } from "node:fs";
import { createServer, request as httpRequest } from "node:http";
import type { IncomingMessage, OutgoingHttpHeaders, ServerResponse } from "node:http";
import { extname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const WEB_PORT = Number(process.env.E2E_WEB_PORT ?? 4180);
const API_URL = new URL(process.env.E2E_API_URL ?? "http://127.0.0.1:8100");
const MAX_BODY_BYTES = 64 * 1024;
const ONE_YEAR_SECONDS = 365 * 24 * 60 * 60;

const frontendDir = fileURLToPath(new URL("../..", import.meta.url));
const distDir = resolve(frontendDir, "dist");

const CONTENT_TYPES: Record<string, string> = {
  ".html": "text/html",
  ".js": "application/javascript",
  ".css": "text/css",
  ".svg": "image/svg+xml",
  ".woff2": "font/woff2",
  ".json": "application/json",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".txt": "text/plain",
};

// nginx hides these three from the backend so the response carries each only once.
const HIDDEN_BACKEND_HEADERS = ["x-content-type-options", "x-frame-options", "referrer-policy"];
const PROXIED_PATH = /^\/(?:api\/|health$|ready$)/;

/** Every `add_header NAME "VALUE" always;` at server level in nginx.conf. */
function readSecurityHeaders(): Record<string, string> {
  const config = readFileSync(resolve(frontendDir, "nginx.conf"), "utf8");
  const headers: Record<string, string> = {};
  for (const match of config.matchAll(/^\s*add_header\s+([A-Za-z-]+)\s+"([^"]*)"\s+always;/gm)) {
    const [, name, value] = match;
    if (name && value !== undefined) headers[name.toLowerCase()] = value;
  }
  if (!headers["content-security-policy"]) {
    throw new Error("nginx.conf declares no Content-Security-Policy; the tests would run unprotected.");
  }
  return headers;
}

const securityHeaders = readSecurityHeaders();

function send(response: ServerResponse, status: number, headers: OutgoingHttpHeaders, body?: string): void {
  response.writeHead(status, { ...headers, ...securityHeaders });
  response.end(body);
}

function resolveFile(pathname: string): string | null {
  let decoded: string;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    return null;
  }
  if (decoded.includes("\0")) return null;
  const candidate = resolve(join(distDir, decoded));
  if (candidate !== distDir && !candidate.startsWith(distDir + sep)) return null;
  try {
    return statSync(candidate).isFile() ? candidate : null;
  } catch {
    return null;
  }
}

function serveFile(request: IncomingMessage, response: ServerResponse, file: string): void {
  const cache =
    file.includes(`${sep}assets${sep}`) ? `public, max-age=${ONE_YEAR_SECONDS}` : "no-cache";
  response.writeHead(200, {
    "content-type": CONTENT_TYPES[extname(file)] ?? "application/octet-stream",
    "content-length": statSync(file).size,
    "cache-control": cache,
    ...securityHeaders,
  });
  if (request.method === "HEAD") {
    response.end();
    return;
  }
  createReadStream(file).pipe(response);
}

function forwardToApi(request: IncomingMessage, response: ServerResponse): void {
  if (Number(request.headers["content-length"] ?? 0) > MAX_BODY_BYTES) {
    send(response, 413, { "content-type": "text/plain" }, "Request body too large");
    request.resume();
    return;
  }
  const upstream = httpRequest(
    {
      hostname: API_URL.hostname,
      port: API_URL.port,
      method: request.method,
      path: request.url,
      headers: { ...request.headers, connection: "close" },
    },
    (reply) => {
      const headers = { ...reply.headers };
      for (const name of HIDDEN_BACKEND_HEADERS) delete headers[name];
      response.writeHead(reply.statusCode ?? 502, { ...headers, ...securityHeaders });
      reply.pipe(response);
    },
  );
  upstream.on("error", () => {
    if (!response.headersSent) send(response, 502, { "content-type": "text/plain" }, "Bad gateway");
    else response.destroy();
  });
  request.pipe(upstream);
}

const server = createServer((request, response) => {
  const { pathname } = new URL(request.url ?? "/", "http://localhost");

  if (pathname === "/nginx-health") {
    send(response, 200, { "content-type": "text/plain" }, "ok\n");
    return;
  }
  if (PROXIED_PATH.test(pathname)) {
    forwardToApi(request, response);
    return;
  }
  if (request.method !== "GET" && request.method !== "HEAD") {
    send(response, 405, { "content-type": "text/plain" }, "Method not allowed");
    return;
  }

  const file = resolveFile(pathname);
  if (file) {
    serveFile(request, response, file);
    return;
  }
  // Missing build output is a real 404; any other path is a client-side route.
  if (pathname.startsWith("/assets/")) {
    send(response, 404, { "content-type": "text/plain" }, "Not found");
    return;
  }
  const index = resolveFile("/index.html");
  if (index) serveFile(request, response, index);
  else send(response, 503, { "content-type": "text/plain" }, "dist/ is missing: run `npm run build`.");
});

server.listen(WEB_PORT, "127.0.0.1");
