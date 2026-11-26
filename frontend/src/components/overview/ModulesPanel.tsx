import Panel from "../hud/Panel";
import StatusLed from "../hud/StatusLed";

interface Module {
  name: string;
  summary: string;
  live: boolean;
}

// What is built is marked Live; everything else is marked Planned rather than shown as working.
const MODULES: readonly Module[] = [
  {
    name: "Threat intelligence",
    summary: "Investigate IPs, domains, URLs and hashes; score and store the results.",
    live: true,
  },
  {
    name: "Network monitoring",
    summary: "Capture live traffic or analyse a PCAP; flows and detection alerts.",
    live: true,
  },
  { name: "Incident management", summary: "Cases, ownership and response workflow.", live: false },
  {
    name: "Secure file sharing",
    summary: "Encrypted storage and expiring, revocable download links.",
    live: true,
  },
  { name: "Administration", summary: "Users, roles and audit review.", live: false },
];

/** The platform's modules and how far along each one is. */
export default function ModulesPanel() {
  return (
    <Panel title="Platform modules" code="MOD">
      <ul role="list" className="grid grid-cols-1 gap-3 @lg:grid-cols-2 @deck:grid-cols-5">
        {MODULES.map((module) => (
          <li
            key={module.name}
            className={`flex flex-col justify-between gap-3 rounded-ui border p-3 ${
              module.live ? "border-ok/40 bg-ok/5" : "border-dashed border-ink-500 bg-ink-900/40"
            }`}
          >
            <div>
              <p className={`flex items-center gap-2 font-medium ${module.live ? "text-ink-50" : "text-ink-200"}`}>
                <StatusLed tone={module.live ? "ok" : "idle"} />
                {module.name}
              </p>
              <p className="mt-1 text-xs text-ink-300">{module.summary}</p>
            </div>
            <span
              className={`self-start rounded-chip border px-2 py-0.5 text-[0.68rem] font-semibold uppercase tracking-[0.12em] ${
                module.live ? "cf-plate border-ok/60 text-ok" : "border-ink-500 text-ink-300"
              }`}
            >
              {module.live ? "Live" : "Planned"}
            </span>
          </li>
        ))}
      </ul>
    </Panel>
  );
}
