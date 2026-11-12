import { useLayoutEffect, useRef, useState } from "react";

import { animate, scrambleText } from "../../motion/anime";
import { useMotion } from "../../motion/useMotion";

/** The characters the text flickers through on its way to the real thing. */
const GLYPHS = "A-Z0-9#%&*+<>/";
/** Longer text is not worth decoding: it would take too long and read as noise. */
const MAX_LENGTH = 160;
const MIN_MS = 380;
const MAX_MS = 800;
const MS_PER_CHARACTER = 28;

function placeholderFor(text: string): string {
  return text.replace(/\S/g, "·");
}

/**
 * Text that resolves out of scrambled characters when visual effects are on, using anime.js's
 * scrambleText. The real text is always what assistive technology reads; the scramble is hidden
 * from it. Once it has settled, what is left is the plain text, exactly as it renders with
 * effects off.
 */
export default function DecodeText({ text, className }: { text: string; className?: string }) {
  const motion = useMotion();
  const scrambled = useRef<HTMLSpanElement>(null);
  /** The text that has finished decoding, so a re-render does not decode it again. */
  const [settled, setSettled] = useState<string | null>(null);
  const decoding = motion && text.length <= MAX_LENGTH && settled !== text;

  useLayoutEffect(() => {
    const element = scrambled.current;
    if (!decoding || element === null) return;
    element.textContent = placeholderFor(text);
    const scramble = animate(element, {
      textContent: scrambleText({
        text,
        chars: GLYPHS,
        duration: Math.min(MAX_MS, Math.max(MIN_MS, text.length * MS_PER_CHARACTER)),
        settleDuration: 240,
      }),
      onComplete: () => setSettled(text),
    });
    return () => {
      scramble.cancel();
    };
  }, [decoding, text]);

  if (!decoding) {
    return (
      <span key="plain" className={className}>
        {text}
      </span>
    );
  }
  return (
    <>
      {/* React never renders children into this one: the scramble writes into it directly. */}
      <span key="scrambling" ref={scrambled} aria-hidden="true" className={className} />
      <span key="reading" className="sr-only">
        {text}
      </span>
    </>
  );
}
