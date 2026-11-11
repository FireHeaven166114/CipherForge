import { type FormEvent, useId, useState } from "react";
import { Link } from "react-router";

import ErrorNotice from "../components/ErrorNotice";
import InvestigationView from "../components/intel/InvestigationView";
import LoadingNote from "../components/LoadingNote";
import { BUTTON, FIELD, PRIMARY_BUTTON } from "../components/styles";
import { CLASSIFICATION_META, isScoreAssessed } from "../features/intel/classification";
import { useDocumentTitle } from "../hooks/useDocumentTitle";
import { type InvestigateState, useInvestigate } from "../hooks/useInvestigate";
import type { Investigation } from "../types/intel";

/** The API rejects longer values. Counting here lets us say so instead of cutting text off. */
const MAX_INDICATOR_LENGTH = 2048;

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

export default function InvestigatePage() {
  useDocumentTitle("Investigate");
  const { state, run } = useInvestigate();
  const [value, setValue] = useState("");
  const [refresh, setRefresh] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const id = useId();
  const helpId = `${id}-help`;
  const problemId = `${id}-problem`;
  const loading = state.status === "loading";

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
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

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Investigate an indicator</h1>
        <p className="mt-1 text-sm text-slate-400">
          Look up an IP address, domain, URL or file hash. Each provider is asked separately, and
          CipherForge then combines their answers into one assessment.
        </p>
      </div>

      <form onSubmit={handleSubmit} noValidate className="space-y-4">
        <div>
          <label htmlFor={id} className="block text-sm font-medium text-slate-200">
            Indicator
          </label>
          <input
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
            className={`${FIELD} mt-1 font-mono`}
          />
          <p id={helpId} className="mt-1 text-xs text-slate-400">
            IPv4, IPv6, domain, URL or SHA-256. Surrounding spaces are ignored. Private, reserved
            and internal addresses and names are not looked up.
          </p>
          {problem !== null ? (
            <p id={problemId} role="alert" className="mt-1 text-sm font-medium text-red-200">
              <span aria-hidden="true">✕ </span>
              {problem}
            </p>
          ) : null}
        </div>

        <div>
          <label className="flex items-start gap-2 text-sm text-slate-200">
            <input
              type="checkbox"
              checked={refresh}
              onChange={(event) => setRefresh(event.target.checked)}
              className="mt-0.5 h-4 w-4 rounded border-slate-500 bg-slate-950 accent-cyan-500 focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400"
            />
            <span>
              Ask the providers again, even if a stored answer is recent
              <span className="block text-xs text-slate-400">
                Every lookup uses part of each provider&apos;s quota. Answers less than a minute
                old are reused either way.
              </span>
            </span>
          </label>
        </div>

        <p className="rounded-md border border-slate-700 bg-slate-900 p-3 text-xs text-slate-300">
          Investigating sends the indicator to each configured threat-intelligence provider, which
          is outside your organisation. Do not submit anything you are not allowed to share, such as
          internal hostnames or URLs that contain tokens.
        </p>

        <button type="submit" disabled={loading} className={PRIMARY_BUTTON}>
          {loading ? "Investigating…" : "Investigate"}
        </button>
      </form>

      <p role="status" className="sr-only">
        {announcement(state)}
      </p>

      {state.status === "loading" ? (
        <LoadingNote>
          Asking the providers about {state.indicator}. This can take up to 30 seconds.
        </LoadingNote>
      ) : null}

      {state.status === "error" ? <ErrorNotice error={state.error} /> : null}

      {state.status === "success" ? (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-800 pt-4">
            <p className="text-sm text-slate-300">
              This result is saved. You can return to it from the Indicators page.
            </p>
            <Link
              to={`/indicators/${encodeURIComponent(state.investigation.indicator.indicator_id)}`}
              className={BUTTON}
            >
              Open the saved record
            </Link>
          </div>
          <InvestigationView investigation={state.investigation} />
        </div>
      ) : null}
    </div>
  );
}
