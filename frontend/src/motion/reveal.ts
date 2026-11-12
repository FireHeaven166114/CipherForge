import { stagger, waapi, type WAAPIAnimation } from "./anime";

/** Panels, tiles and page headers opt in to the entrance with this attribute. */
const SELECTOR = "[data-reveal]";
const DURATION_MS = 640;
/** However many elements arrive together, the last one starts no later than this. */
const MAX_SPREAD_MS = 520;
const MAX_STEP_MS = 70;

/**
 * Elements that have had their entrance. It outlives a director, so switching effects off and on
 * again does not replay the page; an element whose entrance was cut short is taken out of it
 * again, so it gets its entrance on the next start.
 */
const revealed = new WeakSet<Element>();

interface Entrance {
  animation: WAAPIAnimation;
  targets: HTMLElement[];
}

/** Stops an entrance and puts the elements back exactly as React rendered them. */
function finish(entrance: Entrance): void {
  entrance.animation.revert();
}

/**
 * Watches `root` and gives every element that arrives with a `data-reveal` attribute a staggered
 * entrance (fade, rise and settle) with anime.js's Web Animations engine. Elements that arrive in
 * the same render come in as one wave. Because the animation holds the first frame while it
 * waits, nothing flashes at full strength first, and when it ends the inline styles it left are
 * removed, so the finished element is exactly the one that was never animated.
 */
export function startReveal(root: HTMLElement): () => void {
  const running = new Set<Entrance>();
  let queue: HTMLElement[] = [];

  const enqueue = (element: HTMLElement) => {
    if (revealed.has(element)) return;
    revealed.add(element);
    queue.push(element);
  };
  const scan = (node: Node) => {
    if (!(node instanceof HTMLElement)) return;
    if (node.matches(SELECTOR)) enqueue(node);
    node.querySelectorAll<HTMLElement>(SELECTOR).forEach(enqueue);
  };

  const play = () => {
    const targets: HTMLElement[] = [];
    for (const element of queue) {
      if (element.isConnected) targets.push(element);
      // Taken off the page before its wave: it has not had an entrance, so it may still get one.
      else revealed.delete(element);
    }
    queue = [];
    // anime.js warns about an empty target list, and the console must stay silent.
    if (targets.length === 0) return;

    const step = targets.length > 1 ? Math.min(MAX_STEP_MS, MAX_SPREAD_MS / (targets.length - 1)) : 0;
    const entrance: Entrance = {
      targets,
      animation: waapi.animate(targets, {
        opacity: [0, 1],
        transform: ["translateY(16px) scale(0.985)", "translateY(0px) scale(1)"],
        duration: DURATION_MS,
        delay: stagger(step),
        ease: "outExpo",
        onComplete: () => {
          finish(entrance);
          running.delete(entrance);
        },
      }),
    };
    running.add(entrance);
  };

  const observer = new MutationObserver((records) => {
    for (const record of records) record.addedNodes.forEach(scan);
    play();
  });
  observer.observe(root, { childList: true, subtree: true });

  // What is already on the page when the director starts gets its entrance too.
  scan(root);
  play();

  return () => {
    observer.disconnect();
    queue = [];
    for (const entrance of running) {
      finish(entrance);
      for (const element of entrance.targets) revealed.delete(element);
    }
    running.clear();
  };
}
