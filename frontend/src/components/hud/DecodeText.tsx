import { useEffect, useState } from "react";

import { useEffects } from "../../effects/useEffects";

const GLYPHS = "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789#%&*+<>/";
const FRAME_MS = 38;
const MAX_TOTAL_MS = 650;

function placeholderFor(text: string): string {
  return text.replace(/\S/g, "·");
}

interface Progress {
  text: string;
  value: string;
}

/**
 * Text that resolves out of scrambled characters when visual effects are on. The real text is
 * always what assistive technology reads; the scramble is hidden from it.
 */
export default function DecodeText({ text, className }: { text: string; className?: string }) {
  const { enabled } = useEffects();
  const [progress, setProgress] = useState<Progress | null>(null);

  useEffect(() => {
    if (!enabled) return;
    const characters = Array.from(text);
    const perCharacter = Math.min(48, MAX_TOTAL_MS / Math.max(characters.length, 1));
    let start: number | undefined;
    let lastDraw = 0;
    let frame = 0;

    const tick = (now: number) => {
      start ??= now;
      const resolved = Math.floor((now - start) / perCharacter);
      if (resolved >= characters.length) {
        setProgress({ text, value: text });
        return;
      }
      if (now - lastDraw >= FRAME_MS) {
        lastDraw = now;
        const value = characters
          .map((character, index) =>
            index < resolved || /\s/.test(character)
              ? character
              : (GLYPHS[Math.floor(Math.random() * GLYPHS.length)] ?? character),
          )
          .join("");
        setProgress({ text, value });
      }
      frame = requestAnimationFrame(tick);
    };

    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [enabled, text]);

  if (!enabled) return <span className={className}>{text}</span>;
  const shown = progress !== null && progress.text === text ? progress.value : placeholderFor(text);
  if (shown === text) return <span className={className}>{text}</span>;
  return (
    <>
      <span aria-hidden="true" className={className}>
        {shown}
      </span>
      <span className="sr-only">{text}</span>
    </>
  );
}
