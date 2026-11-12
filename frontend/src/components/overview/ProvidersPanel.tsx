import { INDICATOR_TYPE_LABELS } from "../../features/intel/labels";
import type { ProviderInfo } from "../../types/intel";
import Panel from "../hud/Panel";
import StatusBadge from "../StatusBadge";

/** Which threat-intelligence providers are set up, and which answers are made up for a demo. */
export default function ProvidersPanel({ providers }: { providers: readonly ProviderInfo[] }) {
  const configured = providers.filter((provider) => provider.configured);

  return (
    <Panel title="Intelligence providers" code="SRC" className="h-full">
      {configured.length === 0 ? (
        <div role="note" className="mb-3 rounded-ui border border-warn/50 bg-warn/10 p-3 text-sm text-warn">
          <p className="flex items-center gap-2 font-semibold">
            <span aria-hidden="true">▲</span>
            No threat-intelligence provider is configured
          </p>
          <p className="mt-1 text-ink-100">
            Every investigation will come back as &ldquo;Not assessed&rdquo; until an administrator adds a
            provider API key on the server.
          </p>
        </div>
      ) : null}
      <ul role="list" className="divide-y divide-white/10">
        {providers.map((provider) => (
          <li
            key={provider.name}
            className="flex flex-wrap items-center justify-between gap-2 py-2.5 first:pt-0 last:pb-0"
          >
            <div className="min-w-0">
              <p className="font-medium text-ink-50">{provider.display_name}</p>
              <p className="text-xs text-ink-300">
                Handles {provider.supported_types.map((type) => INDICATOR_TYPE_LABELS[type]).join(", ")}
              </p>
            </div>
            {provider.simulated ? (
              <StatusBadge tone="warn">Simulated</StatusBadge>
            ) : (
              <StatusBadge tone={provider.configured ? "ok" : "warn"}>
                {provider.configured ? "Configured" : "Not configured"}
              </StatusBadge>
            )}
          </li>
        ))}
      </ul>
      <p className="mt-3 text-xs text-ink-300">
        {providers.some((provider) => provider.simulated)
          ? "Simulated providers return made-up answers for the development demo. Nothing leaves this machine."
          : "Configured providers receive the indicators you investigate."}
      </p>
    </Panel>
  );
}
