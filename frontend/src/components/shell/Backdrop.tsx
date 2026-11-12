/**
 * The ambient layers behind the console: a soft glow, a faint grid, scanlines and a slow beam.
 * They are purely decorative, never receive input, and are stilled by the effects switch.
 */
export default function Backdrop() {
  return (
    <div aria-hidden="true" className="pointer-events-none fixed inset-0 z-0 overflow-hidden">
      <div className="cf-backdrop absolute inset-0" />
      <div className="cf-grid absolute inset-0" />
      <div className="cf-scanlines absolute inset-0" />
      <div className="cf-beam absolute inset-x-0 top-0 h-[22vh] animate-scan" />
    </div>
  );
}
