import { useApiResource } from "../../hooks/useApiResource";
import { fetchMe } from "../../services/identityService";

// Shown only when the top bar (a size container) is wide enough to hold them beside everything else.
const CHIP =
  "hidden shrink-0 items-center gap-1.5 whitespace-nowrap rounded-[3px] border px-2 py-1 text-[0.68rem] font-semibold uppercase tracking-[0.12em] @min-[75rem]:inline-flex";

/**
 * Who the API thinks you are, as a role (never an id or a name), and whether it is running in
 * development sign-in mode. When the identity cannot be read the chip is simply absent: the page
 * itself explains an access problem where it matters.
 */
export default function IdentityChip() {
  const { state } = useApiResource(fetchMe);

  if (state.status === "loading") return null;
  if (state.status === "error") {
    if (state.error.status !== 401) return null;
    return (
      <span className={`${CHIP} border-warn/60 bg-warn/10 text-warn`}>
        <span aria-hidden="true">▲</span>
        Not signed in
      </span>
    );
  }

  const { roles, auth_mode: authMode } = state.data;
  return (
    <>
      <span className={`${CHIP} max-w-48 border-ink-500 bg-ink-800/70 text-ink-100`}>
        <span aria-hidden="true" className="text-cipher">
          ◇
        </span>
        <span className="truncate">{roles.length > 0 ? roles.join(" · ") : "No role"}</span>
      </span>
      {authMode === "dev" ? (
        <span className={`${CHIP} border-ember/60 bg-ember/10 text-ember`} title="Development sign-in">
          Dev auth
        </span>
      ) : null}
    </>
  );
}
