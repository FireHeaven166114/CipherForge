/** Where the mouse or pen is, as of the latest animation frame. */
export interface PointerPosition {
  x: number;
  y: number;
  /** False once the pointer has left the window, so lights can fade out. */
  inside: boolean;
}

const FINE_POINTER = "(hover: hover) and (pointer: fine)";

/**
 * Watches the mouse or pen and calls `onFrame` at most once per animation frame, however many
 * events arrived, and again when the page scrolls under a pointer that is standing still. A
 * finger has no hover, so touch is ignored (and the whole thing is skipped on touch-only
 * devices): a glow that sticks where the last tap landed would look broken.
 */
export function trackPointer(onFrame: (position: PointerPosition) => void): () => void {
  if (typeof window.matchMedia !== "function" || !window.matchMedia(FINE_POINTER).matches) {
    return () => undefined;
  }

  let x = 0;
  let y = 0;
  let inside = false;
  let frame = 0;

  const flush = () => {
    frame = 0;
    onFrame({ x, y, inside });
  };
  const schedule = () => {
    if (frame === 0) frame = requestAnimationFrame(flush);
  };
  const onMove = (event: PointerEvent) => {
    if (event.pointerType === "touch") return;
    x = event.clientX;
    y = event.clientY;
    inside = true;
    schedule();
  };
  const onLeave = () => {
    if (!inside) return;
    inside = false;
    schedule();
  };
  const onScroll = () => {
    if (inside) schedule();
  };

  window.addEventListener("pointermove", onMove, { passive: true });
  window.addEventListener("scroll", onScroll, { passive: true, capture: true });
  window.addEventListener("blur", onLeave);
  document.documentElement.addEventListener("pointerleave", onLeave);

  return () => {
    window.removeEventListener("pointermove", onMove);
    window.removeEventListener("scroll", onScroll, { capture: true });
    window.removeEventListener("blur", onLeave);
    document.documentElement.removeEventListener("pointerleave", onLeave);
    if (frame !== 0) cancelAnimationFrame(frame);
  };
}
