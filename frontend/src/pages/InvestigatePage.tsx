import { type FormEvent, useEffect, useId, useMemo, useRef, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router";

import ErrorNotice from "../components/ErrorNotice";
import PageHeader from "../components/hud/PageHeader";
import Panel from "../components/hud/Panel";
import StatusLed from "../components/hud/StatusLed";
import InvestigationView from "../components/intel/InvestigationView";
import ScanLoader from "../components/intel/ScanLoader";
import { BUTTON, LABEL, PRIMARY_BUTTON } from "../components/styles";
import { CLASSIFICATION_META, isScoreAssessed } from "../features/intel/classification";
import { guessIndicatorType } from "../features/intel/guess";
import { type InvestigateIntent, readIntent } from "../features/intel/investigateIntent";
import { INDICATOR_TYPE_LABELS } from "../features/intel/labels";
import { MAX_INDICATOR_LENGTH } from "../features/intel/limits";
import { useDocumentTitle } from "../hooks/useDocumentTitle";
import { type InvestigateState, useInvestigate } from "../hooks/useInvestigate";
import type { Investigation } from "../types/intel";

interface Example {
  label: string;
  value: string;
  /** What the chip prints when the value is too long to show in full. */
  preview?: string;
}

/** Public, harmless values. Choosing one only fills the field; nothing is sent until Investigate. */
const EXAMPLES: readonly Example[] = [
  { label: "IPv4", value: "8.8.8.8" },
  { label: "Domain", value: "example.com" },
  { label: "URL", value: "https://example.com/path" },
  // The SHA-256 of an empty file.
  {
    label: "SHA-256",
    value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    preview: "e3b0c442…",
  },
];

const CHIP =
  "cf-glow inline-flex items-center gap-1.5 rounded-chip border border-white/10 bg-ink-900/60 px-2.5 py-1 text-xs font-medium text-ink-100 transition hover:border-cipher/50 hover:bg-ink-800 hover:text-ink-50";

function describeResult(investigation: Investigation): string {
  const { indicator, score } = investigation;
  if (!isScoreAssessed(score)) {
    return `${indicator.indicator_value} was not assessed because no provider answered.`;
  }
  const label = CLASSIFICATION_META[score.classification].label;
  return `${indicator.indicator_value} is classified ${label}, with score ${score.score} and confidence ${score.confidence}.`;
}

/** Text for a live region that stays on the page, so changes to it are announced. */
function announcement(state: InvestigateState): string {
  switch (state.status) {
    case "loading":
      return `Investigating ${state.indicator}.`;
    case "success":
      return describeResult(state.investigation);
    default:
      return "";
  }
}

function Scanner({ intent }: { intent: InvestigateIntent | null }) {
  const navigate = useNavigate();
  const { pathname, search, hash } = useLocation();
  // Read once, when the scanner is created: it is what makes the lookup start on arrival.
  const { state, run } = useInvestigate(
    intent?.autorun ? { indicator: intent.indicator, refresh: false } : undefined,
  );
  const [value, setValue] = useState(intent?.indicator ?? "");
  const [refresh, setRefresh] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const id = useId();
  const helpId = `${id}-help`;
  const problemId = `${id}-problem`;
  const examplesId = `${id}-examples`;
  const loading = state.status === "loading";
  const guess = guessIndicatorType(value);

  // The lookup has begun, so the request is spent. Clearing it in the history entry means that
  // reloading the page, or coming back to it later, fills the field without asking providers again.
  useEffect(() => {
    if (intent?.autorun) {
      void navigate({ pathname, search, hash }, { replace: true, state: { ...intent, autorun: false } });
    }
  }, [intent, navigate, pathname, search, hash]);

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    // Enter in the field submits too, and a lookup in flight must not be restarted.
    if (loading) return;
    const indicator = value.trim();
    if (indicator === "") {
      setProblem("Enter an indicator to investigate.");
      return;
    }
    if (indicator.length > MAX_INDICATOR_LENGTH) {
      setProblem(
        `An indicator can be at most ${MAX_INDICATOR_LENGTH} characters. This one has ${indicator.length}.`,
      );
      return;
    }
    setProblem(null);
    run(indicator, refresh);
  }

  function fillExample(example: string) {
    setValue(example);
    setProblem(null);
    inputRef.current?.focus();
  }

  return (
    <div className="space-y-6">
      <PageHeader
        code="MOD-02 · THREAT SCANNER"
        title="Investigate an indicator"
        description="Look up an IP address, domain, URL or file hash. Each provider is asked separately, and CipherForge then combines their answers into one assessment."
      />

      <Panel title="Indicator scanner" code="SCAN" bodyClassName="p-5">
        <form onSubmit={handleSubmit} noValidate className="space-y-5">
          <div>
            <label htmlFor={id} className={`${LABEL} block`}>
              Indicator
            </label>
            <div className="mt-2 flex items-center rounded-ui border border-ink-500 bg-void/70 transition focus-within:border-cipher focus-within:shadow-glow">
              <span aria-hidden="true" className="select-none pl-3 font-mono text-lg text-cipher">
                ❯
              </span>
              <input
                ref={inputRef}
                id={id}
                name="indicator"
                type="text"
                value={value}
                onChange={(event) => setValue(event.target.value)}
                autoComplete="off"
                autoCapitalize="off"
                spellCheck={false}
                placeholder="8.8.8.8, example.com, https://example.com/path or a SHA-256 hash"
                aria-invalid={problem !== null}
                aria-describedby={problem === null ? helpId : `${helpId} ${problemId}`}
                className="min-w-0 flex-1 bg-transparent px-3 py-3 font-mono text-base text-ink-50 outline-hidden placeholder:text-ink-300"
              />
              {guess !== null ? (
                <span className="mr-3 shrink-0 rounded-chip border border-cipher/40 bg-cipher/10 px-1.5 py-0.5 font-mono text-[0.7rem] tracking-wide text-cipher">
                  <span className="sr-only">Looks like </span>
                  {INDICATOR_TYPE_LABELS[guess]}
                </span>
              ) : null}
            </div>
            <p id={helpId} className="mt-2 text-xs text-ink-300">
              IPv4, IPv6, domain, URL or SHA-256. Surrounding spaces are ignored. Private, reserved
              and internal addresses and names are not looked up.
            </p>
            {problem !== null ? (
              <p id={problemId} role="alert" className="mt-2 text-sm font-medium text-bad">
                <span aria-hidden="true">✕ </span>
                {problem}
              </p>
            ) : null}
          </div>

          <div role="group" aria-labelledby={examplesId} className="flex flex-wrap items-center gap-2">
            <span id={examplesId} className={LABEL}>
              Fill with an example
            </span>
            {EXAMPLES.map((example) => (
              <button
                key={example.label}
                type="button"
                onClick={() => fillExample(example.value)}
                className={CHIP}
              >
                {example.label} <span className="font-mono text-ink-300">{example.preview ?? example.value}</span>
              </button>
            ))}
          </div>

          <label className="flex items-start gap-3 text-sm text-ink-100">
            <input
              type="checkbox"
              checked={refresh}
              onChange={(event) => setRefresh(event.target.checked)}
              className="mt-0.5 size-4 shrink-0 rounded-sm accent-cipher"
            />
            <span>
              Ask the providers again, even if a stored answer is recent
              <span className="block text-xs text-ink-300">
                Every lookup uses part of each provider&apos;s quota. Answers less than a minute
                old are reused either way.
              </span>
            </span>
          </label>

          <p className="rounded-ui border border-warn/40 bg-warn/5 p-3 text-xs text-ink-200">
            <span className="font-semibold text-warn">Before you send: </span>
            Investigating sends the indicator to each configured threat-intelligence provider, which
            is outside your organisation. Do not submit anything you are not allowed to share, such as
            internal hostnames or URLs that contain tokens.
          </p>

          <button type="submit" aria-disabled={loading || undefined} className={PRIMARY_BUTTON}>
            {loading ? "Investigating…" : "Investigate"}
          </button>
        </form>
      </Panel>

      <p role="status" className="sr-only">
        {announcement(state)}
      </p>

      {state.status === "loading" ? <ScanLoader indicator={state.indicator} /> : null}

      {state.status === "error" ? <ErrorNotice error={state.error} /> : null}

      {state.status === "success" ? (
        <div className="space-y-5">
          <div
            data-reveal
            className="flex flex-wrap items-center justify-between gap-3 rounded-ui border border-white/10 bg-ink-900/50 px-4 py-3"
          >
            <p className="flex items-center gap-2 text-sm text-ink-200">
              <StatusLed tone="ok" />
              This result is saved. You can return to it from the Indicators page.
            </p>
            <Link
              to={`/indicators/${encodeURIComponent(state.investigation.indicator.indicator_id)}`}
              className={BUTTON}
            >
              Open the saved record
              <span aria-hidden="true">→</span>
            </Link>
          </div>
          <InvestigationView investigation={state.investigation} />
        </div>
      ) : null}
    </div>
  );
}

export default function InvestigatePage() {
  useDocumentTitle("Investigate");
  const { state } = useLocation();
  const intent = useMemo(() => readIntent(state), [state]);

  // Every request from the command palette gets a scanner of its own, so asking about the same
  // indicator twice looks it up twice. Clearing the autorun flag later keeps the same key.
  const key = intent === null ? "scanner" : `${intent.indicator}:${intent.nonce}`;
  return <Scanner key={key} intent={intent} />;
}
