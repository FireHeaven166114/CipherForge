import { createAnimatable } from "./anime";

const ACTIVE_LINK = 'a[aria-current="page"]';
const GLIDE_MS = 560;

export interface Lamp {
  /** Moves the lamp onto the link of the page that is open, gliding or, when `glide` is false, at once. */
  aim: (glide: boolean) => void;
  stop: () => void;
}

/**
 * The "tubelight" of the navigation: a lit pill that glides from one link to the next with an
 * anime.js animatable instead of the active link simply changing colour. `track` is the
 * positioned element that holds the links, and `lamp` is placed inside it. If the open page has
 * no link (the not-found page), the lamp goes dark. The links are measured again whenever the
 * track or a link changes size, so the lamp stays put on the right link when the window is
 * resized, the text is enlarged or the layout switches between the phone bar and the rail.
 */
export function createLamp(track: HTMLElement, lamp: HTMLElement): Lamp {
  const glide = { duration: GLIDE_MS, ease: "out(4)" };
  const slider = createAnimatable(lamp, {
    x: glide,
    y: glide,
    width: glide,
    height: glide,
    opacity: { duration: 280, ease: "out(2)" },
  });

  const aim = (animated: boolean) => {
    const link = track.querySelector<HTMLElement>(ACTIVE_LINK);
    const duration = animated ? undefined : 0;
    if (link === null) {
      slider.opacity?.(0, duration);
      return;
    }
    // Boxes are measured to the sub-pixel: on a phone four tabs share 390px, and a lamp rounded to
    // whole pixels would end up past the edge of the window.
    const box = link.getBoundingClientRect();
    const home = track.getBoundingClientRect();
    slider.x?.(box.left - home.left - track.clientLeft, duration);
    slider.y?.(box.top - home.top - track.clientTop, duration);
    slider.width?.(box.width, duration);
    slider.height?.(box.height, duration);
    slider.opacity?.(1, duration);
  };

  const observer = new ResizeObserver(() => aim(false));
  observer.observe(track);
  track.querySelectorAll("a").forEach((link) => observer.observe(link));

  return {
    aim,
    stop: () => {
      observer.disconnect();
      slider.revert();
    },
  };
}
