import { trackPointer } from "./pointer";

/** Panels, buttons and links that catch the light carry one of these classes (see index.css). */
const LIT_SELECTOR = ".hud-panel, .cf-glow";
/** How far outside its edge an element already starts to react to the pointer, in pixels. */
const REACH_PX = 140;

/**
 * Lets glass panels, buttons and links catch the pointer: while it is near an element, the
 * element gets `--mx` / `--my` (the pointer's place inside it) and `data-lit`, and the stylesheet
 * draws the spotlight and the glowing border from those. Elements that are far away are left
 * alone, and every element is reset when the pointer leaves or the director stops.
 */
export function startPanelGlow(): () => void {
  let lit = new Set<HTMLElement>();

  const stop = trackPointer(({ x, y, inside }) => {
    const candidates = inside ? Array.from(document.querySelectorAll<HTMLElement>(LIT_SELECTOR)) : [];
    // Read every rectangle before writing anything, so the layout is worked out only once.
    const measured = candidates.map((element) => ({ element, rect: element.getBoundingClientRect() }));

    const next = new Set<HTMLElement>();
    for (const { element, rect } of measured) {
      const near =
        x >= rect.left - REACH_PX &&
        x <= rect.right + REACH_PX &&
        y >= rect.top - REACH_PX &&
        y <= rect.bottom + REACH_PX;
      if (!near) continue;
      next.add(element);
      element.style.setProperty("--mx", `${(x - rect.left).toFixed(1)}px`);
      element.style.setProperty("--my", `${(y - rect.top).toFixed(1)}px`);
      if (!lit.has(element)) element.setAttribute("data-lit", "");
    }
    for (const element of lit) {
      if (!next.has(element)) element.removeAttribute("data-lit");
    }
    lit = next;
  });

  return () => {
    stop();
    for (const element of lit) element.removeAttribute("data-lit");
    lit.clear();
  };
}
