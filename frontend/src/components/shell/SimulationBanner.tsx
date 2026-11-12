import { useApiResource } from "../../hooks/useApiResource";
import { getStats } from "../../services/intelService";

/**
 * A strip across the top whenever the API's providers are simulated, so made-up demo data can
 * never be mistaken for real threat intelligence. It is silent when the answer is unavailable:
 * the pages report their own errors.
 */
export default function SimulationBanner() {
  const { state } = useApiResource(getStats);
  if (state.status !== "success" || !state.data.providers.some((provider) => provider.simulated)) {
    return null;
  }
  return (
    <section
      aria-label="Demo data notice"
      className="relative z-10 border-b border-ember/40 bg-ember/10 px-4 py-1.5 text-center text-[0.7rem] font-semibold uppercase tracking-[0.16em] text-ember"
    >
      <span aria-hidden="true">▲ </span>
      Simulated providers: this is demo data, not real threat intelligence
    </section>
  );
}
