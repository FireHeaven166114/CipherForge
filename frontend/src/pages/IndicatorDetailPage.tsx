import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useParams } from "react-router";

import ErrorNotice from "../components/ErrorNotice";
import { TrashIcon } from "../components/hud/Icons";
import PageHeader from "../components/hud/PageHeader";
import DeleteIndicatorsDialog from "../components/intel/DeleteIndicatorsDialog";
import InvestigationView from "../components/intel/InvestigationView";
import LoadingNote from "../components/LoadingNote";
import { BUTTON, DANGER_BUTTON, LINK } from "../components/styles";
import { describeDeletion } from "../features/intel/deletion";
import { useApiResource } from "../hooks/useApiResource";
import { useDeleteIndicators } from "../hooks/useDeleteIndicators";
import { useDocumentTitle } from "../hooks/useDocumentTitle";
import { useInvestigate } from "../hooks/useInvestigate";
import { getIndicator } from "../services/intelService";
import type { DeleteResult } from "../types/intel";

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

/** Takes the place of the record once it is deleted: the page it was on has nothing left to show. */
function Deleted({ result }: { result: DeleteResult }) {
  const region = useRef<HTMLDivElement>(null);

  // The delete button that held focus is gone with the record, so focus would fall to the page.
  useEffect(() => {
    region.current?.focus();
  }, []);

  const alreadyGone = result.deleted.length === 0;
  return (
    <div ref={region} tabIndex={-1} className="space-y-4 focus:outline-none">
      <BackLink />
      <PageHeader
        code="MOD-03 · INDICATOR DOSSIER"
        title={alreadyGone ? "Indicator already gone" : "Indicator deleted"}
        description={describeDeletion(result)}
        actions={
          <>
            <Link to="/indicators" className={BUTTON}>
              Back to the list
            </Link>
            <Link to="/investigate" className={BUTTON}>
              Investigate another indicator
            </Link>
          </>
        }
      />
      <p className="max-w-3xl text-xs text-ink-300">
        The audit log is kept as it is: it still records the past lookups and gains a record of this
        deletion.
      </p>
    </div>
  );
}

function IndicatorDetail({ id }: { id: string }) {
  const load = useCallback((signal: AbortSignal) => getIndicator(id, signal), [id]);
  const { state, reload } = useApiResource(load);
  const recheck = useInvestigate();
  const deletion = useDeleteIndicators();
  const [confirming, setConfirming] = useState(false);
  const [deleted, setDeleted] = useState<DeleteResult | null>(null);

  // A finished re-check is newer than the stored record, so it replaces it on screen.
  const stored = state.status === "success" ? state.data : null;
  const investigation = recheck.state.status === "success" ? recheck.state.investigation : stored;
  const rechecking = recheck.state.status === "loading";

  const value = investigation?.indicator.indicator_value;
  // Re-checking a record that was deleted in the meantime stores a new one under a new ID, and
  // the new one is what is on screen, so that is what "Delete" must remove.
  const shownId = investigation?.indicator.indicator_id ?? id;
  useDocumentTitle(
    deleted !== null
      ? "Indicator deleted"
      : value
        ? `Indicator ${value.slice(0, MAX_TITLE_VALUE)}`
        : "Indicator",
  );

  function askToDelete() {
    deletion.reset();
    setConfirming(true);
  }

  function cancelDelete() {
    deletion.reset();
    setConfirming(false);
  }

  async function confirmDelete() {
    const result = await deletion.run([shownId]);
    // A failure leaves the dialog open, showing why, so the analyst can try again or give up.
    if (result === null) return;
    setConfirming(false);
    setDeleted(result);
  }

  if (deleted !== null) return <Deleted result={deleted} />;

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
              <>
                <button
                  type="button"
                  aria-disabled={rechecking || undefined}
                  onClick={rechecking ? undefined : () => recheck.run(investigation.indicator.indicator_value, true)}
                  className={BUTTON}
                >
                  {rechecking ? "Re-checking…" : "Re-check with providers"}
                </button>
                <button
                  type="button"
                  aria-disabled={rechecking || undefined}
                  onClick={rechecking ? undefined : askToDelete}
                  className={DANGER_BUTTON}
                >
                  <TrashIcon className="size-4" />
                  Delete indicator
                </button>
              </>
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
      {investigation ? (
        <InvestigationView
          investigation={investigation}
          onRetry={() => recheck.run(investigation.indicator.indicator_value, false)}
          retrying={rechecking}
        />
      ) : null}

      <DeleteIndicatorsDialog
        targets={confirming && value !== undefined ? [{ id: shownId, value }] : null}
        busy={deletion.busy}
        error={deletion.error}
        onConfirm={() => void confirmDelete()}
        onCancel={cancelDelete}
      />
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
