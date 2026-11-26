import type { ApiError } from "../services/apiClient";
import { deleteSession } from "../services/networkService";
import { useNetworkAction } from "./useNetworkAction";

async function removeSession(sessionId: string): Promise<true> {
  await deleteSession(sessionId);
  return true;
}

export interface DeleteSessionControls {
  /** True from the moment a deletion starts until the API has answered. */
  busy: boolean;
  /** Why the last deletion failed, until the next one starts or `reset` is called. */
  error: ApiError | null;
  /** Resolves to true once the session is gone, or to null when it failed (see `error`) or the screen went away. */
  remove: (sessionId: string) => Promise<true | null>;
  reset: () => void;
}

/** Deletes finished sessions one at a time. A confirmed deletion is left to finish if the page goes away. */
export function useNetworkDelete(): DeleteSessionControls {
  const { busy, error, run, reset } = useNetworkAction(removeSession);
  return { busy, error, remove: run, reset };
}
