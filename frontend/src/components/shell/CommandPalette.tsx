import { type KeyboardEvent, useId, useMemo, useState } from "react";
import { useNavigate } from "react-router";

import { useEffects } from "../../effects/useEffects";
import { createIntent } from "../../features/intel/investigateIntent";
import Kbd from "../hud/Kbd";
import { SearchIcon } from "../hud/Icons";
import Overlay from "../hud/Overlay";
import { type PaletteItem, buildPaletteItems } from "./paletteItems";

interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
}

function PaletteBody({ onClose }: { onClose: () => void }) {
  const navigate = useNavigate();
  const { enabled, forcedOff, toggle } = useEffects();
  const [query, setQuery] = useState("");
  const [cursor, setCursor] = useState(0);
  const listId = useId();

  const items = useMemo(
    () => buildPaletteItems(query, { enabled, locked: forcedOff }),
    [query, enabled, forcedOff],
  );
  const active = items.length === 0 ? -1 : Math.min(cursor, items.length - 1);

  const run = (item: PaletteItem) => {
    onClose();
    const { action } = item;
    switch (action.kind) {
      case "go":
        void navigate(action.to);
        break;
      case "investigate":
        // Passed in router state rather than the address, so a lookup is never started by a link.
        void navigate("/investigate", { state: createIntent(action.indicator) });
        break;
      case "search":
        void navigate({ pathname: "/indicators", search: `?${new URLSearchParams({ q: action.query })}` });
        break;
      case "effects":
        toggle();
        break;
    }
  };

  const onKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      if (items.length === 0) return;
      const step = event.key === "ArrowDown" ? 1 : -1;
      setCursor((active + step + items.length) % items.length);
    } else if (event.key === "Enter") {
      event.preventDefault();
      const item = items[active];
      if (item !== undefined) run(item);
    }
  };

  return (
    <div className="hud-panel overflow-hidden rounded-[3px] shadow-glow">
      <div className="flex items-center gap-3 border-b border-ink-700 px-4">
        <SearchIcon className="size-5 shrink-0 text-cipher" />
        <input
          type="text"
          role="combobox"
          aria-label="Search commands or enter an indicator"
          aria-expanded="true"
          aria-controls={listId}
          aria-autocomplete="list"
          aria-activedescendant={active >= 0 ? `${listId}-${active}` : undefined}
          autoComplete="off"
          spellCheck={false}
          maxLength={2048}
          placeholder="Jump to a page, or type an indicator to investigate"
          value={query}
          onChange={(event) => {
            setQuery(event.target.value);
            setCursor(0);
          }}
          onKeyDown={onKeyDown}
          className="h-14 min-w-0 flex-1 bg-transparent text-base text-ink-50 placeholder:text-ink-300 focus:outline-none"
        />
        <span aria-hidden="true">
          <Kbd>Esc</Kbd>
        </span>
      </div>
      <ul id={listId} role="listbox" aria-label="Commands" className="max-h-80 overflow-y-auto p-2">
        {items.map((item, index) => (
          <li
            key={item.id}
            id={`${listId}-${index}`}
            role="option"
            aria-selected={index === active}
            onMouseMove={() => setCursor(index)}
            onClick={() => run(item)}
            className={`flex cursor-pointer items-center justify-between gap-4 rounded-[3px] border px-3 py-2.5 text-sm ${
              index === active
                ? "border-cipher/50 bg-cipher/10 text-ink-50"
                : "border-transparent text-ink-200"
            }`}
          >
            <span className="min-w-0 truncate">{item.label}</span>
            <span className="shrink-0 font-mono text-[0.7rem] text-ink-300">{item.hint}</span>
          </li>
        ))}
      </ul>
      <p aria-hidden="true" className="border-t border-ink-700 px-4 py-2 text-xs text-ink-300">
        ↑ ↓ move · Enter run · Esc close
      </p>
    </div>
  );
}

/**
 * Jump anywhere, or hand an indicator to the Investigate page, from the keyboard. It is a dialog
 * with a combobox: arrow keys move through the options and Enter runs the highlighted one.
 */
export default function CommandPalette({ open, onClose }: CommandPaletteProps) {
  return (
    <Overlay open={open} onClose={onClose} label="Command palette" placement="top">
      <PaletteBody onClose={onClose} />
    </Overlay>
  );
}
