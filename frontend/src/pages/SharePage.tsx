import { useCallback } from "react";
import { useParams } from "react-router";

import ShareOffer from "../components/files/ShareOffer";
import SharePageFrame from "../components/files/SharePageFrame";
import ShareStateMessage from "../components/files/ShareStateMessage";
import LoadingNote from "../components/LoadingNote";
import { type ShareFailure, classifyShareError } from "../features/files/shareStates";
import { useApiResource } from "../hooks/useApiResource";
import { useDocumentTitle } from "../hooks/useDocumentTitle";
import { useShareNoIndex } from "../hooks/useShareNoIndex";
import { getShareInfo } from "../services/shareService";

const NOT_FOUND: ShareFailure = { kind: "not_found", waitSeconds: undefined, reference: undefined };

/** Looks the link up and shows what it offers. It starts afresh for every token. */
function ShareView({ token }: { token: string }) {
  const load = useCallback((signal: AbortSignal) => getShareInfo(token, signal), [token]);
  const { state, reload } = useApiResource(load);

  if (state.status === "loading") return <LoadingNote>Checking this link…</LoadingNote>;
  if (state.status === "error") {
    return <ShareStateMessage failure={classifyShareError(state.error)} variant="page" onRetry={reload} />;
  }
  return <ShareOffer token={token} info={state.data} />;
}

/**
 * The public page a share link opens. It sits outside the console on purpose: no navigation, no
 * sign-in, and no request carries credentials. The token in the address is the only secret here, so
 * it goes to the API in the request path and is never shown, logged or put in the page title.
 */
export default function SharePage() {
  const { token } = useParams();
  // A fixed title: neither the token nor the file's name belongs in browser history or a tab strip.
  useDocumentTitle("Shared file");
  useShareNoIndex();

  return (
    <SharePageFrame>
      {token === undefined || token === "" ? (
        <ShareStateMessage failure={NOT_FOUND} variant="page" />
      ) : (
        <ShareView key={token} token={token} />
      )}
    </SharePageFrame>
  );
}
