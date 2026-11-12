import { useCallback } from "react";
import { Link, useParams } from "react-router";

import ErrorNotice from "../components/ErrorNotice";
import PageHeader from "../components/hud/PageHeader";
import InvestigationView from "../components/intel/InvestigationView";
import LoadingNote from "../components/LoadingNote";
import { BUTTON, LINK } from "../components/styles";
import { useApiResource } from "../hooks/useApiResource";
import { useDocumentTitle } from "../hooks/useDocumentTitle";
import { useInvestigate } from "../hooks/useInvestigate";
import { getIndicator } from "../services/intelService";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MAX_TITLE_VALUE = 60;

function BackLink() {
  return (
    <Link to="/indicators" className={`${LINK} inline-block text-sm`}>
      <span aria-hidden="true">← </span>All indicators
    </Link>
  );
}

function NotFound({ title, message }: { title: string; message: string }) {
  useDocumentTitle(title);
  return (
    <div className="space-y-4">
      <BackLink />
      <PageHeader code="ERR-404 · NO RECORD" title={title} description={message} />
    </div>
  );
}

function IndicatorDetail({ id }: { id: string }) {
  const load = useCallback((signal: AbortSignal) => getIndicator(id, signal), [id]);
  const { state, reload } = useApiResource(load);
  const recheck = useInvestigate();

  // A finished re-check is newer than the stored record, so it replaces it on screen.
  const stored = state.status === "success" ? state.data : null;
  const investigation = recheck.state.status === "success" ? recheck.state.investigation : stored;
  const rechecking = recheck.state.status === "loading";

  const value = investigation?.indicator.indicator_value;
  useDocumentTitle(value ? `Indicator ${value.slice(0, MAX_TITLE_VALUE)}` : "Indicator");

  if (state.status === "error" && state.error.status === 404) {
    return (
      <NotFound
        title="Indicator not found"
        message="No stored indicator has this ID. It may have been removed, or the link may be wrong."
      />
    );
  }

  return (
    <div className="space-y-6">
      <div className="space-y-4">
        <BackLink />
        <PageHeader
          code="MOD-03 · INDICATOR DOSSIER"
          title="Indicator details"
          description="This is the stored record. Re-checking asks the configured providers again and updates it."
          actions={
            investigation ? (
              <button
                type="button"
                aria-disabled={rechecking || undefined}
                onClick={rechecking ? undefined : () => recheck.run(investigation.indicator.indicator_value, true)}
                className={BUTTON}
              >
                {rechecking ? "Re-checking…" : "Re-check with providers"}
              </button>
            ) : undefined
          }
        />
      </div>

      <p role="status" className="sr-only">
        {rechecking ? "Re-checking with the providers." : ""}
        {recheck.state.status === "success" ? "Re-check complete. The record was updated." : ""}
      </p>

      {recheck.state.status === "error" ? <ErrorNotice error={recheck.state.error} /> : null}

      {state.status === "loading" ? <LoadingNote>Loading the stored record…</LoadingNote> : null}
      {state.status === "error" ? <ErrorNotice error={state.error} onRetry={reload} /> : null}
      {investigation ? <InvestigationView investigation={investigation} /> : null}
    </div>
  );
}

export default function IndicatorDetailPage() {
  const { indicatorId = "" } = useParams();

  if (!UUID.test(indicatorId)) {
    return (
      <NotFound
        title="Indicator not found"
        message="That is not a valid indicator ID. Open an indicator from the list instead."
      />
    );
  }
  // Keyed so that moving from one indicator to another never carries over a re-check result.
  return <IndicatorDetail key={indicatorId} id={indicatorId} />;
}
