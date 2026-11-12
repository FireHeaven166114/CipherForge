import { createAnimatable, createTimer, waapi } from "./anime";
import { createField } from "./field";
import { trackPointer, type PointerPosition } from "./pointer";

/** How far, in pixels, the orbs lean away from a pointer at the edge of the window. */
const LEAN_X = 26;
const LEAN_Y = 18;
const FIELD_FPS = 30;
/** One cell of the grid in index.css (.cf-grid-plane). Sliding by exactly this much loops without a seam. */
const GRID_CELL_PX = 64;

/** Where each orb wanders to and back, and how long a one-way trip takes. */
const DRIFT = [
  { to: "translate3d(9vw, 7vh, 0) scale(1.16)", duration: 23_000 },
  { to: "translate3d(-8vw, 9vh, 0) scale(1.12)", duration: 29_000 },
  { to: "translate3d(6vw, -8vh, 0) scale(1.2)", duration: 34_000 },
] as const;

function layer<T extends HTMLElement>(root: HTMLElement, name: string): T | null {
  return root.querySelector<T>(`[data-layer="${name}"]`);
}

/**
 * Brings the layers of the background (see components/shell/Atmosphere.tsx) to life with anime.js:
 *
 * - the orbs drift and breathe, and the grid floor slides toward the viewer, as endless Web
 *   Animations that run on the compositor;
 * - the orbs lean a little away from the pointer, and a soft light follows it (anime.js
 *   animatables, so both ease toward the pointer instead of snapping to it);
 * - a field of drifting dots is drawn on a canvas from an anime.js timer at 30 frames a second.
 *
 * The layers are found by their data-layer attribute. Everything that is started is stopped, and
 * every inline style put right again, by the function this returns.
 */
export function startAtmosphere(root: HTMLElement): () => void {
  const stops: Array<() => void> = [];
  const parallax = layer(root, "parallax");
  const plane = layer(root, "plane");
  const cursor = layer(root, "cursor");
  const canvas = layer<HTMLCanvasElement>(root, "field");

  root.querySelectorAll<HTMLElement>('[data-layer="orb"]').forEach((orb, index) => {
    const drift = DRIFT[index % DRIFT.length];
    if (drift === undefined) return;
    const animation = waapi.animate(orb, {
      transform: ["translate3d(0, 0, 0) scale(1)", drift.to],
      duration: drift.duration,
      ease: "inOutSine",
      alternate: true,
      loop: true,
    });
    stops.push(() => animation.revert());
  });

  if (plane !== null) {
    const animation = waapi.animate(plane, {
      transform: ["translateY(0px)", `translateY(${GRID_CELL_PX}px)`],
      duration: 3600,
      ease: "linear",
      loop: true,
    });
    stops.push(() => animation.revert());
  }

  const lean =
    parallax === null
      ? null
      : createAnimatable(parallax, { x: { duration: 1100, ease: "out(3)" }, y: { duration: 1100, ease: "out(3)" } });
  const light =
    cursor === null
      ? null
      : createAnimatable(cursor, {
          x: { duration: 420, ease: "out(3)" },
          y: { duration: 420, ease: "out(3)" },
          opacity: { duration: 500, ease: "out(2)" },
        });
  if (lean !== null) stops.push(() => lean.revert());
  if (light !== null) stops.push(() => light.revert());

  const field = canvas === null ? null : createField(canvas);
  if (field !== null) {
    field.resize();
    window.addEventListener("resize", field.resize);
    let last = performance.now();
    const timer = createTimer({
      frameRate: FIELD_FPS,
      onUpdate: () => {
        const now = performance.now();
        field.draw(now - last);
        last = now;
      },
    });
    stops.push(() => {
      timer.cancel();
      window.removeEventListener("resize", field.resize);
      field.clear();
    });
  }

  let placed = false;
  const follow = ({ x, y, inside }: PointerPosition) => {
    field?.setPointer({ x, y, inside });
    const width = Math.max(window.innerWidth, 1);
    const height = Math.max(window.innerHeight, 1);
    lean?.x?.(inside ? -(x / width - 0.5) * 2 * LEAN_X : 0);
    lean?.y?.(inside ? -(y / height - 0.5) * 2 * LEAN_Y : 0);
    if (inside) {
      // The first sighting of the pointer jumps to it, so the light does not sweep in from a corner.
      const duration = placed ? undefined : 0;
      light?.x?.(x, duration);
      light?.y?.(y, duration);
      placed = true;
    } else {
      placed = false;
    }
    light?.opacity?.(inside ? 1 : 0);
  };
  stops.push(trackPointer(follow));

  return () => {
    for (const stop of stops.reverse()) stop();
  };
}
