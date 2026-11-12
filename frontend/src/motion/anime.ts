/**
 * The one place the app imports anime.js (MIT, https://animejs.com) from, so the rest of the code
 * depends on a small surface and the library is bundled from a single spot. Everything that moves
 * in the console goes through here: the reveal choreography, counting numbers, decoding headings,
 * the sliding navigation lamp, the drifting atmosphere and the particle field.
 *
 * Nothing in src/motion starts unless the visual-effects switch is on (see effects/useEffects),
 * and nothing writes to the console, so a failure to animate can only ever mean "no animation".
 */
export { animate, createAnimatable, createTimer, scrambleText, stagger, waapi } from "animejs";
export type { WAAPIAnimation } from "animejs";

/**
 * True when the browser can run the Web Animations based engine anime.js offers (waapi.animate).
 * It needs Element.animate and registered custom properties. Without them the page simply stays
 * still, which is also what happens in the unit-test DOM.
 */
export function canAnimate(): boolean {
  return (
    typeof Element !== "undefined" &&
    typeof Element.prototype.animate === "function" &&
    typeof CSS !== "undefined" &&
    typeof CSS.registerProperty === "function"
  );
}
