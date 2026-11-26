import type { LiveState } from "../../hooks/useLiveResource";
import type { ActivityList as ActivityData } from "../../types/files";
import ErrorNotice from "../ErrorNotice";
import { RefreshIcon } from "../hud/Icons";
import Panel from "../hud/Panel";
import LoadingNote from "../LoadingNote";
import { BUTTON } from "../styles";
import ActivityList from "./ActivityList";

interface FileActivityPanelProps {
  state: LiveState<ActivityData>;
  onRefresh: () => void;
}

/** The audit trail of one file: uploads, links made and used, refusals and failed checks. */
export default function FileActivityPanel({ state, onRefresh }: FileActivityPanelProps) {
  const refreshing = state.status === "ready" && state.refreshing;

  return (
    <Panel
      title="Activity"
      code="LOG"
      bodyClassName="p-0"
      actions={
        <button
          type="button"
          aria-disabled={refreshing || undefined}
          onClick={refreshing ? undefined : onRefresh}
          className={BUTTON}
        >
          <RefreshIcon className="size-4" />
          {refreshing ? "Refreshing…" : "Refresh"} <span className="sr-only">activity</span>
        </button>
      }
    >
      {state.status === "loading" ? (
        <div className="p-4">
          <LoadingNote>Loading activity…</LoadingNote>
        </div>
      ) : null}

      {state.status === "error" ? (
        <div className="p-4">
          <ErrorNotice error={state.error} onRetry={onRefresh} />
        </div>
      ) : null}

      {state.status === "ready" ? (
        <>
          {state.refreshError ? (
            <p role="alert" className="px-4 pt-4 text-warn">
              Activity could not be refreshed ({state.refreshError.message}). This is what was loaded
              earlier.
            </p>
          ) : null}
          {state.data.items.length === 0 ? (
            <p className="p-4">Nothing has been recorded for this file yet.</p>
          ) : (
            <ActivityList items={state.data.items} />
          )}
        </>
      ) : null}
    </Panel>
  );
}
