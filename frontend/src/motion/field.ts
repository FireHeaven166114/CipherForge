import type { PointerPosition } from "./pointer";

/** Cipher cyan, arc violet and pulse magenta: the three accents of the console, as RGB. */
const PALETTE: ReadonlyArray<readonly [number, number, number]> = [
  [56, 232, 255],
  [165, 139, 255],
  [255, 107, 214],
];
/** Cyan is the main accent, so it gets most of the dots. */
const PALETTE_ODDS = [0.5, 0.85, 1];

/** Particles closer than this, in pixels, are joined by a line that fades with the distance. */
const LINK_DISTANCE = 150;
/** The pointer pushes dots away inside this radius and draws lines to the ones just outside it. */
const PUSH_RADIUS = 130;
const POINTER_LINK_DISTANCE = 210;
const MAX_STEP_MS = 64;
const EDGE_MARGIN = 24;

interface Particle {
  x: number;
  y: number;
  /** Cruising speed in pixels per millisecond. */
  vx: number;
  vy: number;
  /** Speed borrowed from the pointer's push. It dies away on its own. */
  kx: number;
  ky: number;
  radius: number;
  colour: number;
  phase: number;
  twinkle: number;
}

/** How many dots a screen of this size gets: sparse enough to stay calm, dense enough to link up. */
export function particleCountFor(width: number, height: number): number {
  return Math.max(18, Math.min(72, Math.round((width * height) / 24_000)));
}

export interface Field {
  /** Fits the canvas to its box (call it again when the window changes size). */
  resize: () => void;
  setPointer: (pointer: PointerPosition) => void;
  /** Moves every dot on by `elapsedMs` and paints one frame. */
  draw: (elapsedMs: number) => void;
  /** Wipes the canvas. */
  clear: () => void;
}

function rgba([r, g, b]: readonly [number, number, number], alpha: number): string {
  return `rgba(${r},${g},${b},${alpha.toFixed(3)})`;
}

/**
 * The "signal field" layer of the background: a few dozen glowing dots that drift upward, twinkle
 * and join up with faint lines when they pass close to each other. The pointer nudges the dots
 * aside and gets lines to the ones near it. It is plain Canvas 2D (the console's content-security
 * policy has no use for WebGL, workers or blobs), drawn from an anime.js timer at a capped frame
 * rate. Returns null when the browser gives no 2D context.
 */
export function createField(canvas: HTMLCanvasElement, random: () => number = Math.random): Field | null {
  const context = canvas.getContext("2d");
  if (context === null) return null;

  let width = 1;
  let height = 1;
  let clock = 0;
  let particles: Particle[] = [];
  const pointer: PointerPosition = { x: 0, y: 0, inside: false };

  const spawn = (): Particle => {
    const roll = random();
    const colour = PALETTE_ODDS.findIndex((limit) => roll < limit);
    return {
      x: random() * width,
      y: random() * height,
      vx: (random() - 0.5) * 0.018,
      vy: -(0.004 + random() * 0.014),
      kx: 0,
      ky: 0,
      radius: 0.8 + random() * 1.5,
      colour: colour === -1 ? 0 : colour,
      phase: random() * Math.PI * 2,
      twinkle: 0.0006 + random() * 0.0012,
    };
  };

  const resize = () => {
    const box = canvas.getBoundingClientRect();
    width = Math.max(1, Math.round(box.width));
    height = Math.max(1, Math.round(box.height));
    const scale = Math.min(window.devicePixelRatio || 1, 1.5);
    canvas.width = Math.round(width * scale);
    canvas.height = Math.round(height * scale);
    context.setTransform(scale, 0, 0, scale, 0, 0);

    const wanted = particleCountFor(width, height);
    while (particles.length < wanted) particles.push(spawn());
    particles = particles.slice(0, wanted);
    for (const particle of particles) {
      particle.x = Math.min(particle.x, width);
      particle.y = Math.min(particle.y, height);
    }
  };

  const move = (particle: Particle, step: number) => {
    if (pointer.inside) {
      const dx = particle.x - pointer.x;
      const dy = particle.y - pointer.y;
      const distance = Math.hypot(dx, dy);
      if (distance > 1 && distance < PUSH_RADIUS) {
        const push = (1 - distance / PUSH_RADIUS) * 0.0006 * step;
        particle.kx += (dx / distance) * push;
        particle.ky += (dy / distance) * push;
      }
    }
    const decay = Math.exp(-step / 420);
    particle.kx *= decay;
    particle.ky *= decay;
    particle.x += (particle.vx + particle.kx) * step;
    particle.y += (particle.vy + particle.ky) * step;
    if (particle.x < -EDGE_MARGIN) particle.x = width + EDGE_MARGIN;
    else if (particle.x > width + EDGE_MARGIN) particle.x = -EDGE_MARGIN;
    if (particle.y < -EDGE_MARGIN) particle.y = height + EDGE_MARGIN;
    else if (particle.y > height + EDGE_MARGIN) particle.y = -EDGE_MARGIN;
  };

  const line = (colour: number, alpha: number, fromX: number, fromY: number, toX: number, toY: number) => {
    context.strokeStyle = rgba(PALETTE[colour] ?? PALETTE[0] ?? [56, 232, 255], alpha);
    context.beginPath();
    context.moveTo(fromX, fromY);
    context.lineTo(toX, toY);
    context.stroke();
  };

  const draw = (elapsedMs: number) => {
    const step = Math.min(Math.max(elapsedMs, 0), MAX_STEP_MS);
    clock += step;
    for (const particle of particles) move(particle, step);

    context.clearRect(0, 0, width, height);
    context.globalCompositeOperation = "lighter";
    context.lineWidth = 1;

    for (let i = 0; i < particles.length; i++) {
      const a = particles[i];
      if (a === undefined) continue;
      for (let j = i + 1; j < particles.length; j++) {
        const b = particles[j];
        if (b === undefined) continue;
        const distance = Math.hypot(a.x - b.x, a.y - b.y);
        if (distance < LINK_DISTANCE) line(a.colour, (1 - distance / LINK_DISTANCE) ** 2 * 0.3, a.x, a.y, b.x, b.y);
      }
      if (pointer.inside) {
        const distance = Math.hypot(a.x - pointer.x, a.y - pointer.y);
        if (distance < POINTER_LINK_DISTANCE) {
          line(0, (1 - distance / POINTER_LINK_DISTANCE) * 0.45, a.x, a.y, pointer.x, pointer.y);
        }
      }
    }

    for (const particle of particles) {
      const colour = PALETTE[particle.colour] ?? PALETTE[0] ?? [56, 232, 255];
      const glow = 0.5 + 0.5 * Math.sin(clock * particle.twinkle + particle.phase);
      const alpha = 0.3 + 0.55 * glow;
      context.fillStyle = rgba(colour, alpha * 0.14);
      context.beginPath();
      context.arc(particle.x, particle.y, particle.radius * 4.5, 0, Math.PI * 2);
      context.fill();
      context.fillStyle = rgba(colour, alpha);
      context.beginPath();
      context.arc(particle.x, particle.y, particle.radius, 0, Math.PI * 2);
      context.fill();
    }
    context.globalCompositeOperation = "source-over";
  };

  return {
    resize,
    setPointer: (next) => {
      pointer.x = next.x;
      pointer.y = next.y;
      pointer.inside = next.inside;
    },
    draw,
    clear: () => context.clearRect(0, 0, width, height),
  };
}
