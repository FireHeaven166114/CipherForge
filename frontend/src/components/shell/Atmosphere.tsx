import { useLayoutEffect, useRef } from "react";

import { startAtmosphere } from "../../motion/atmosphere";
import { useMotion } from "../../motion/useMotion";

/**
 * The living background behind the console, back to front: a mesh gradient, three drifting orbs,
 * a perspective grid floor, a field of drifting dots (a canvas), a soft light under the pointer,
 * film grain and a vignette. The layer stack follows the layer categories GetLayers.io publishes;
 * the markup and the code are original. It is purely decorative: hidden from assistive technology,
 * deaf to the pointer, and still unless visual effects are on. The canvas and the pointer light
 * exist only while they are on, so with effects off the page carries no animated layers at all.
 */
export default function Atmosphere() {
  const motion = useMotion();
  const root = useRef<HTMLDivElement>(null);

  useLayoutEffect(() => {
    const element = root.current;
    if (!motion || element === null) return;
    return startAtmosphere(element);
  }, [motion]);

  return (
    <div ref={root} aria-hidden="true" className="cf-atmosphere">
      <div className="cf-backdrop" />
      <div data-layer="parallax" className="cf-parallax">
        <div data-layer="orb" className="cf-orb cf-orb-a" />
        <div data-layer="orb" className="cf-orb cf-orb-b" />
        <div data-layer="orb" className="cf-orb cf-orb-c" />
      </div>
      <div className="cf-grid">
        <div data-layer="plane" className="cf-grid-plane" />
      </div>
      {motion ? <canvas data-layer="field" className="cf-field" /> : null}
      {motion ? <div data-layer="cursor" className="cf-cursor" /> : null}
      <div className="cf-grain" />
      <div className="cf-vignette" />
    </div>
  );
}
