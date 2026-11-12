import { useEffect, useRef } from "react";
import { useNavigate } from "react-router";

/** Two-key "go to" shortcuts: press G, then one of these keys within a second. */
const GO_TO: Readonly<Record<string, string>> = {
  o: "/",
  i: "/investigate",
  l: "/indicators",
  s: "/status",
};
const SEQUENCE_WINDOW_MS = 1000;

function isTyping(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  return target.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName);
}

/** A modal overlay makes the page behind it inert, which is the signal to stand down. */
function overlayIsOpen(): boolean {
  return document.getElementById("root")?.hasAttribute("inert") ?? false;
}

interface Shortcuts {
  /** Ctrl+K or Cmd+K. */
  onTogglePalette: () => void;
  /** The "/" key. */
  onOpenPalette: () => void;
}

/**
 * Console-wide keyboard shortcuts. Plain keys never fire while typing in a field, with a modifier
 * held, or while a dialog is open, so they cannot get in the way of normal text entry.
 */
export function useShortcuts({ onTogglePalette, onOpenPalette }: Shortcuts): void {
  const navigate = useNavigate();
  const handlers = useRef({ onTogglePalette, onOpenPalette, navigate });

  useEffect(() => {
    handlers.current = { onTogglePalette, onOpenPalette, navigate };
  });

  useEffect(() => {
    let goPressedAt = 0;

    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && !event.altKey && event.key.toLowerCase() === "k") {
        event.preventDefault();
        handlers.current.onTogglePalette();
        return;
      }
      if (event.ctrlKey || event.metaKey || event.altKey || event.repeat || event.defaultPrevented) return;
      if (isTyping(event.target) || overlayIsOpen()) {
        goPressedAt = 0;
        return;
      }

      const key = event.key.toLowerCase();
      if (key === "/") {
        event.preventDefault();
        handlers.current.onOpenPalette();
        return;
      }
      if (goPressedAt !== 0 && Date.now() - goPressedAt <= SEQUENCE_WINDOW_MS) {
        const destination = GO_TO[key];
        goPressedAt = 0;
        if (destination !== undefined) {
          event.preventDefault();
          void handlers.current.navigate(destination);
        }
        return;
      }
      goPressedAt = key === "g" ? Date.now() : 0;
    };

    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, []);
}
