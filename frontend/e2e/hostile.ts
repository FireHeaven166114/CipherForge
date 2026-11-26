import type { Page } from "@playwright/test";

import type {
  FacetEntry,
  Indicator,
  Investigation,
  Overview,
  ProviderInfo,
  ProviderView,
} from "../src/types/intel";
import { TYPE_ORDER } from "./api";
import { expect } from "./fixtures";
import { bandOf } from "./text";

/**
 * Data written to do harm: strings that turn into markup, a script, a link or a broken layout the
 * moment any part of the app stops treating them as text. Everything a provider sends (names,
 * tags, notes, messages, even an indicator's own value) comes from a community feed, so none of it
 * can be trusted, however well formed the response around it is.
 */

export type Kind = "markup" | "scheme" | "encoded" | "handler" | "frame";
export const KINDS: readonly Kind[] = ["markup", "scheme", "encoded", "handler", "frame"];

// Every payload that runs sets this, naming the field it came from, so a failure says where.
const mark = (field: string): string => `window.__pwned='${field}'`;

/** A string that is harmful if it is ever read as markup, a URL, an attribute or code. */
export function attack(kind: Kind, field: string): string {
  switch (kind) {
    case "markup":
      return `"><img src=x onerror="${mark(field)}"><script>${mark(field)}</script>`;
    case "scheme":
      return `javascript:${mark(field)}`;
    case "encoded":
      return `&lt;b&gt;${field}&lt;/b&gt; &#60;i&#62; %3Cu%3E {{constructor.constructor('alert(1)')()}} \${alert(1)}`;
    case "handler":
      return `x" onmouseover="${mark(field)}" autofocus onfocus="${mark(field)}`;
    case "frame":
      return `<iframe src="http://evil.example/${field}"></iframe><a href="javascript:${mark(field)}">${field}</a>`;
  }
}

/** The strings the builders fill a response with: harmful ones, or ones far too long. */
export interface Words {
  /** A name, tag, note or message. */
  text(field: string, kind?: Kind): string;
  /** An indicator value. */
  value(field: string, kind?: Kind): string;
}

export const ATTACKS: Words = {
  text: (field, kind = "markup") => attack(kind, field),
  value: (field, kind = "markup") => attack(kind, field),
};

/** One unbroken token, so there is nowhere for a line to wrap. */
export const LONG: Words = {
  text: (field) => `${field}_${"W".repeat(300)}`,
  value: (field) => `https://example.net/${field}/${"W".repeat(1800)}`,
};

/** IDs that pass the client's UUID check, so a link to them is followed instead of refused. */
export const SAMPLE_ID = (n: number): string => `5c0ffee0-0000-4000-8000-${String(n).padStart(12, "0")}`;
export const DOSSIER_ID = SAMPLE_ID(1);
/** An ID that tries to climb out of the path and start a query and a fragment of its own. */
export const TRAVERSAL_ID = "../../evil?x=1#frag";

const OVERVIEW_URL = "**/api/v1/intel/overview";
const VALID_TIME = "2026-05-14T12:00:00Z";

interface KeyedKind {
  key: string;
  kind: Kind;
}

function entry(words: Words, group: string, { key, kind }: KeyedKind, rank: number, sample: number): FacetEntry {
  const risk = Math.max(5, 95 - rank * 10);
  return {
    key,
    count: Math.max(1, 10 - rank),
    max_risk: risk,
    samples: [
      {
        indicator_id: SAMPLE_ID(sample),
        indicator_type: "url",
        indicator_value: words.value(`${group}-sample-${kind}-${rank}`, kind),
        risk_score: risk,
        classification: bandOf(risk),
      },
    ],
  };
}

export interface HostileFacets {
  countries: FacetEntry[];
  malware: FacetEntry[];
  techniques: FacetEntry[];
  tags: FacetEntry[];
}

/** Ranked lists whose keys are hostile, most frequent first, each with a hostile sample indicator. */
export function hostileFacets(words: Words): HostileFacets {
  const plain = (key: string, kind: Kind = "markup"): KeyedKind => ({ key, kind });
  const hostile = (group: string): KeyedKind[] =>
    KINDS.map((kind) => ({ key: words.text(`${group}-key-${kind}`, kind), kind }));
  const build = (group: string, first: number, keys: readonly KeyedKind[]): FacetEntry[] =>
    keys.map((key, rank) => entry(words, group, key, rank, first + rank));

  return {
    // Names an object inherits are keys the map and the lists must treat as unknown countries.
    countries: build("country", 40, [
      plain("NL"),
      plain("constructor", "handler"),
      plain("__proto__", "scheme"),
      plain("toString", "encoded"),
      plain("hasOwnProperty", "frame"),
      plain("valueOf"),
      ...hostile("country").slice(0, 2),
    ]),
    malware: build("malware", 10, hostile("malware")),
    techniques: build("technique", 20, [
      plain("T1059.001"),
      ...hostile("technique"),
      plain("javascript:alert(1)"),
      plain("T1059/001"),
      plain("t1059"),
      plain("T1059.0011"),
    ]),
    tags: build("tag", 30, hostile("tag")),
  };
}

function indicator(
  words: Words,
  id: string,
  field: string,
  kind: Kind,
  rank: number,
  checked: string | null,
): Indicator {
  const risk = 95 - rank * 10;
  return {
    indicator_id: id,
    indicator_type: "url",
    indicator_value: words.value(`${field}-value`, kind),
    risk_score: risk,
    classification: bandOf(risk),
    confidence: 70,
    first_seen: words.text("unread-first-seen", kind),
    last_seen: words.text("unread-last-seen", kind),
    source_count: 2,
    tags: [words.text(`${field}-tag`, kind)],
    status: "active",
    created_at: VALID_TIME,
    scored_at: VALID_TIME,
    last_checked_at: checked,
  };
}

/** The two short lists of indicators. The first "highest risk" entry has a hostile ID. */
export function hostileIndicators(words: Words, list: "top" | "recent"): Indicator[] {
  const fiveMinutesAgo = new Date(Date.now() - 5 * 60_000).toISOString();
  return KINDS.map((kind, rank) => {
    const id = list === "top" && rank === 0 ? TRAVERSAL_ID : SAMPLE_ID((list === "top" ? 50 : 60) + rank);
    const unreadable = words.text("unread-checked", kind);
    // Unreadable, never checked, a real time, unreadable, never checked.
    const checked = list === "top" ? unreadable : [unreadable, null, fiveMinutesAgo, unreadable, null][rank] ?? null;
    return indicator(words, id, `${list}-${kind}`, kind, rank, checked);
  });
}

export function hostileProviders(words: Words): ProviderInfo[] {
  return [
    {
      name: "evil-intel",
      display_name: words.text("provider-one", "markup"),
      configured: true,
      supported_types: ["url", "domain"],
      simulated: false,
    },
    {
      name: "evil-intel-two",
      display_name: words.text("provider-two", "frame"),
      configured: false,
      supported_types: [...TYPE_ORDER],
      simulated: false,
    },
  ];
}

/** Keys an object has by inheritance, and a hostile one, in the records that count by band and type. */
const INHERITED_NAMES = ["__proto__", "constructor", "toString", "hasOwnProperty"] as const;

function withExtraCounts(counts: Record<string, number>, words: Words): Record<string, number> {
  const extras = Object.fromEntries([
    ...INHERITED_NAMES.map((name, index) => [name, index + 1] as const),
    [words.text("count-key"), 9],
  ]);
  return { ...counts, ...extras };
}

/** The overview with extra, unknown keys in every record that counts by a known key. */
export function overviewWithExtraCounts(base: Overview, words: Words): Overview {
  return {
    ...base,
    by_classification: withExtraCounts(base.by_classification, words),
    by_type: withExtraCounts(base.by_type, words),
    matrix: base.matrix.map((row) => ({ ...row, counts: withExtraCounts(row.counts, words) })),
  };
}

/** The real overview with every community-supplied name, value and link replaced by hostile ones. */
export function hostileOverview(base: Overview, words: Words): Overview {
  const facets = hostileFacets(words);
  return {
    ...overviewWithExtraCounts(base, words),
    countries: facets.countries,
    malware_families: facets.malware,
    attack_techniques: facets.techniques,
    tags: facets.tags,
    top_risk: hostileIndicators(words, "top"),
    recent: hostileIndicators(words, "recent"),
    providers: [...base.providers, ...hostileProviders(words)],
  };
}

/** Serves the real overview with a change applied, so the rest of the page stays genuine. */
export async function serveOverview(page: Page, change: (overview: Overview) => Overview): Promise<void> {
  await page.route(OVERVIEW_URL, async (route) => {
    const response = await route.fetch();
    await route.fulfill({ status: 200, json: change((await response.json()) as Overview) });
  });
}

export interface HostileDossier {
  dossier: Investigation;
  /** Strings the page has to show, exactly as written. */
  shown: string[];
  /** Tokens from values the page cannot read (dates); none may appear anywhere on the page. */
  unread: string[];
}

/** A stored dossier in which every provider-supplied field is hostile. */
export function hostileDossier(words: Words): HostileDossier {
  const shown: string[] = [];
  const unread: string[] = [];
  const say = (field: string, kind: Kind): string => {
    const text = words.text(field, kind);
    shown.push(text);
    return text;
  };
  const silent = (field: string, kind: Kind = "markup"): string => {
    unread.push(`unread-${field}`);
    return words.text(`unread-${field}`, kind);
  };

  const value = words.value("dossier-value", "markup");
  shown.push(value);

  const abuse: ProviderView = {
    provider: "abuseipdb",
    display_name: say("abuse-name", "markup"),
    status: "ok",
    freshness: "fresh",
    signal: 0.87,
    fetched_at: VALID_TIME,
    evidence_at: silent("evidence-at"),
    first_evidence_at: silent("first-evidence-at", "scheme"),
    cache_expires_at: VALID_TIME,
    from_cache: false,
    summary: {
      confidence_score: 87,
      total_reports: 41,
      distinct_reporters: 12,
      window_days: 90,
      last_reported_at: silent("last-reported", "handler"),
      is_whitelisted: false,
      is_tor: true,
      usage_type: say("abuse-usage", "scheme"),
      isp: say("abuse-isp", "encoded"),
      domain: say("abuse-domain", "handler"),
      country_code: say("abuse-country", "frame"),
      notes: [say("abuse-note", "markup")],
    },
    tags: [say("abuse-tag-one", "markup"), say("abuse-tag-two", "handler")],
    message: say("abuse-message", "encoded"),
    verdict: null,
    reason: null,
  };

  // Only the first is a technique ID. The rest are shown as plain text and never as a link.
  const attackIds = ["T1059.001", `javascript:${mark("attack-scheme")}`, "T1059/001", "t1059", "T1059.0011"];
  shown.push(...attackIds, "(unnamed pulse)");

  const otx: ProviderView = {
    provider: "otx",
    display_name: say("otx-name", "scheme"),
    status: "ok",
    freshness: "stale",
    signal: 0.5,
    fetched_at: VALID_TIME,
    evidence_at: VALID_TIME,
    first_evidence_at: null,
    cache_expires_at: null,
    from_cache: true,
    summary: {
      pulse_count: 3,
      pulses_analyzed: 2,
      top_pulses: [
        // The only entry whose ID is a real pulse ID, so the only one that may become a link.
        { id: "5C0FFEE0AAAAAAAAAAAAAAAA", name: say("pulse-linked", "markup"), created: VALID_TIME, modified: silent("pulse-modified") },
        { id: `javascript:${mark("pulse-scheme")}`, name: say("pulse-scheme", "scheme"), created: VALID_TIME },
        { id: "../../evil", name: say("pulse-path", "handler"), created: VALID_TIME },
        { id: "5c0ffee0bbbbbbbbbbbbbbbb\n", name: say("pulse-newline", "encoded"), created: VALID_TIME },
        { id: 12, name: { nested: "not text" }, created: VALID_TIME },
      ],
      validation: [
        { source: say("validation-source", "frame"), message: say("validation-message", "markup") },
        { source: 5, message: null },
      ],
      malware_families: [say("otx-family-one", "encoded"), say("otx-family-two", "handler")],
      attack_ids: [...attackIds, say("attack-markup", "frame")],
      notes: [say("otx-note", "scheme")],
    },
    tags: [say("otx-tag", "frame")],
    message: null,
    verdict: null,
    reason: null,
  };

  // Valid links on the two providers that build their own: the only ones that may be drawn. The
  // other record on each is written as a link that must not become one.
  const virustotal: ProviderView = {
    provider: "virustotal",
    display_name: say("vt-name", "handler"),
    status: "ok",
    freshness: "fresh",
    signal: 0.62,
    fetched_at: VALID_TIME,
    evidence_at: silent("vt-evidence-at", "frame"),
    first_evidence_at: silent("vt-first-evidence-at", "markup"),
    cache_expires_at: VALID_TIME,
    from_cache: false,
    summary: {
      verdict: "malicious",
      analysis_status: "completed",
      malicious: 9,
      suspicious: 2,
      harmless: 50,
      undetected: 14,
      timeout: 1,
      engines_total: 76,
      reputation: -30,
      last_analysis_at: VALID_TIME,
      first_submission_at: VALID_TIME,
      times_submitted: 4,
      categories: [say("vt-category", "markup")],
      threat_label: say("vt-threat-label", "scheme"),
      threat_names: [say("vt-threat-name", "encoded")],
      file_name: say("vt-file-name", "handler"),
      file_type: say("vt-file-type", "frame"),
      country_code: say("vt-country", "markup"),
      asn: 64500,
      as_owner: say("vt-as-owner", "scheme"),
      provider_id: say("vt-provider-id", "encoded"),
      provider_link: "https://www.virustotal.com/gui/domain/example.net",
      malware_families: [say("vt-family", "handler")],
      notes: [say("vt-note", "frame")],
    },
    tags: [say("vt-tag", "markup")],
    message: say("vt-message", "scheme"),
    verdict: "malicious",
    reason: null,
  };

  // The reporter's address is the one thing a reporter chooses freely. It is written out defanged
  // and never linked, so a hostile one cannot lead anywhere.
  const reference = "https://reports.evil.example/path?a=1";
  shown.push("hxxps://reports.evil.example/path?a=1");
  const threatfox: ProviderView = {
    provider: "threatfox",
    display_name: say("tf-name", "frame"),
    status: "ok",
    freshness: "fresh",
    signal: 0.9,
    fetched_at: VALID_TIME,
    evidence_at: VALID_TIME,
    first_evidence_at: null,
    cache_expires_at: null,
    from_cache: true,
    summary: {
      verdict: "malicious",
      match_count: 2,
      highest_confidence: 90,
      association: "indicator",
      matches: [
        {
          id: "1234567",
          ioc: say("tf-ioc-linked", "markup"),
          ioc_type: say("tf-ioc-type", "scheme"),
          threat_type: say("tf-threat-type", "handler"),
          malware: say("tf-malware", "encoded"),
          malware_aliases: [say("tf-alias", "frame")],
          confidence_level: 90,
          first_seen: silent("tf-first-seen", "scheme"),
          last_seen: VALID_TIME,
          reporter: say("tf-reporter", "markup"),
          reference,
          malpedia_url: "https://malpedia.caad.fkie.fraunhofer.de/details/win.examplebot",
          tags: [say("tf-tag", "handler")],
        },
        {
          id: `javascript:${mark("tf-id")}`,
          ioc: say("tf-ioc-unlinked", "scheme"),
          ioc_type: null,
          threat_type: null,
          malware: null,
          malware_aliases: [],
          confidence_level: 40,
          first_seen: null,
          last_seen: null,
          reporter: null,
          reference: say("tf-reference", "frame"),
          malpedia_url: "https://evil.example/details/win.examplebot",
          tags: [],
        },
      ],
      threat_types: [say("tf-threat-types", "markup")],
      malware_families: [say("tf-family", "scheme")],
      notes: [say("tf-note", "encoded")],
    },
    tags: [say("tf-provider-tag", "handler")],
    message: null,
    verdict: "malicious",
    reason: null,
  };

  const failed: ProviderView = {
    provider: "evil-intel",
    display_name: say("evil-name", "handler"),
    status: "error",
    freshness: null,
    signal: null,
    fetched_at: null,
    evidence_at: null,
    first_evidence_at: null,
    cache_expires_at: null,
    from_cache: false,
    summary: {},
    tags: [],
    message: say("evil-message", "markup"),
    verdict: null,
    reason: "unavailable",
  };

  const dossier: Investigation = {
    indicator: {
      indicator_id: DOSSIER_ID,
      indicator_type: "url",
      indicator_value: value,
      risk_score: 77,
      classification: "high",
      confidence: 64,
      first_seen: silent("first-seen", "encoded"),
      last_seen: silent("last-seen", "frame"),
      source_count: 2,
      tags: [say("dossier-tag-one", "scheme"), say("dossier-tag-two", "encoded"), say("dossier-tag-three", "frame")],
      status: "active",
      created_at: VALID_TIME,
      scored_at: VALID_TIME,
      last_checked_at: silent("last-checked", "markup"),
    },
    providers: [abuse, otx, virustotal, threatfox, failed],
    score: {
      methodology: say("methodology", "scheme"),
      score: 77,
      classification: "high",
      confidence: 64,
      answered_sources: 4,
      contributing_sources: 4,
      supporting_sources: 4,
      factors: [
        { code: attack("markup", "factor-code"), label: say("factor-label-one", "encoded"), points: 40, detail: say("factor-detail-one", "markup") },
        { code: attack("handler", "factor-code-two"), label: say("factor-label-two", "handler"), points: 37, detail: say("factor-detail-two", "frame") },
      ],
      uncertainty: [say("uncertain-one", "scheme"), say("uncertain-two", "markup")],
      recommended_actions: [say("action-one", "frame"), say("action-two", "handler")],
      scored_at: VALID_TIME,
    },
    internal_evidence: { available: false, message: say("internal-message", "encoded") },
  };

  return { dossier, shown, unread };
}

/** Serves a hostile dossier for the one ID the hostile lists link to. */
export async function serveHostileDossier(page: Page, words: Words): Promise<HostileDossier> {
  const hostile = hostileDossier(words);
  await page.route(`**/api/v1/intel/indicators/${DOSSIER_ID}`, (route) =>
    route.fulfill({ status: 200, json: hostile.dossier }),
  );
  return hostile;
}

/**
 * Everything in the page that could load, run or navigate somewhere, other than what the app
 * itself puts there: frames, embeds, images, scripts other than the app's bundle, event handlers,
 * and links that lead anywhere but a page of the app, an on-page anchor, or the sites the app builds
 * links to itself (OTX, ATT&CK, VirusTotal, ThreatFox, Malpedia). Each finding says what it is and
 * shows the markup.
 */
export function activeContent(page: Page): Promise<string[]> {
  return page.evaluate(() => {
    const found: string[] = [];
    const TAGS = new Set([
      "iframe", "frame", "frameset", "object", "embed", "applet", "portal", "base", "img", "picture",
      "video", "audio", "source", "track", "style", "foreignobject", "animate", "animatemotion",
      "animatetransform", "set",
    ]);
    const BANNED_ATTRIBUTES = new Set([
      "srcdoc", "action", "formaction", "ping", "poster", "data", "srcset", "background", "manifest", "codebase",
    ]);
    const URL_ATTRIBUTES = new Set(["href", "xlink:href", "src"]);
    const SAFE_URLS = [
      // A path on this site. Backslashes and whitespace are refused outright: a browser reads
      // "/\host" and "/<tab>/host" as "//host", a link to another site.
      /^\/(?![/\\])[^\s\\]*$/,
      /^#/,
      /^https:\/\/otx\.alienvault\.com\/pulse\/[0-9a-f]{24}$/,
      /^https:\/\/attack\.mitre\.org\/techniques\/T\d{4}(?:\/\d{3})?\/$/,
      /^https:\/\/www\.virustotal\.com\/gui\/(?:ip-address|domain|url|file)\/[A-Za-z0-9._:%-]{1,256}$/,
      /^https:\/\/threatfox\.abuse\.ch\/ioc\/\d{1,12}\/$/,
      /^https:\/\/malpedia\.caad\.fkie\.fraunhofer\.de\/(?:details|actor)\/[a-z0-9_.-]{1,96}$/,
    ];
    const BUNDLE = /^\/assets\/[\w.-]+\.js$/;

    const report = (element: Element, why: string): void => {
      found.push(`${why}: ${element.outerHTML.slice(0, 160)}`);
    };

    for (const element of document.querySelectorAll("*")) {
      const tag = element.localName.toLowerCase();
      if (TAGS.has(tag)) report(element, `a <${tag}> element`);
      if (tag === "script" && !(BUNDLE.test(element.getAttribute("src") ?? "") && element.textContent === "")) {
        report(element, "a script that is not the app's bundle");
      }
      if (tag === "meta" && element.hasAttribute("http-equiv")) report(element, "a meta http-equiv");

      for (const attribute of Array.from(element.attributes)) {
        const name = attribute.name.toLowerCase();
        if (name.startsWith("on")) report(element, `an event handler (${name})`);
        else if (BANNED_ATTRIBUTES.has(name)) report(element, `the ${name} attribute`);
        else if (URL_ATTRIBUTES.has(name) && !SAFE_URLS.some((safe) => safe.test(attribute.value))) {
          report(element, `an unsafe URL in ${name}`);
        }
      }

      const target = element.getAttribute("target");
      if (target !== null && target !== "_self") {
        const tokens = (element.getAttribute("rel") ?? "").toLowerCase().split(/\s+/);
        if (!tokens.includes("noopener") || !tokens.includes("noreferrer")) {
          report(element, "a link that opens a new tab without noopener and noreferrer");
        }
      }
    }
    return found;
  });
}

const openedDialogs = new WeakMap<Page, string[]>();

/** Records, and dismisses, any alert, confirm or prompt the page raises. Call it before the page loads. */
export function watchDialogs(page: Page): void {
  const opened: string[] = [];
  openedDialogs.set(page, opened);
  page.on("dialog", (dialog) => {
    opened.push(`${dialog.type()}: ${dialog.message()}`);
    void dialog.dismiss();
  });
}

/**
 * Passes when nothing the page was given has run, loaded or navigated anywhere, and nothing has
 * come out as "NaN", "undefined" or "[object Object]" in the text or in a drawn shape.
 */
export async function expectInert(page: Page, what: string): Promise<void> {
  expect(await activeContent(page), `${what}: active content in the page`).toEqual([]);
  expect(
    await page.evaluate(() => Reflect.get(window, "__pwned") as unknown),
    `${what}: a payload ran script (window.__pwned names the field)`,
  ).toBeUndefined();
  expect(openedDialogs.get(page) ?? [], `${what}: the page raised a dialog`).toEqual([]);

  const garbage = await page.evaluate(() => {
    const found: string[] = [];
    const words = /\b(?:NaN|undefined|Infinity|Invalid Date)\b|\[object Object\]/;
    const text = document.body.textContent ?? "";
    const spoiled = words.exec(text);
    if (spoiled !== null) found.push(`text contains "${spoiled[0]}"`);
    const GEOMETRY = new Set([
      "d", "cx", "cy", "r", "rx", "ry", "x", "y", "x1", "x2", "y1", "y2", "width", "height", "transform",
      "points", "viewbox", "stroke-dasharray", "stroke-dashoffset", "offset",
    ]);
    for (const shape of document.querySelectorAll("svg, svg *")) {
      for (const attribute of Array.from(shape.attributes)) {
        if (GEOMETRY.has(attribute.name.toLowerCase()) && /NaN|undefined|Infinity/.test(attribute.value)) {
          found.push(`<${shape.localName} ${attribute.name}="${attribute.value.slice(0, 40)}">`);
        }
      }
    }
    return found;
  });
  expect(garbage, `${what}: broken text or shapes`).toEqual([]);
}
