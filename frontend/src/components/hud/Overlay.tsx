import { type ReactNode, type RefObject, useEffect, useRef } from "react";
import { createPortal } from "react-dom";

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

// Overlays can stack (the palette over a drawer). Only the topmost one reacts to Escape, and the
// page behind is locked and made inert while at least one is open.
const stack: symbol[] = [];

function lockPage(): void {
  document.documentElement.classList.add("overflow-hidden");
  document.getElementById("root")?.setAttribute("inert", "");
}

function unlockPage(): void {
  document.documentElement.classList.remove("overflow-hidden");
  document.getElementById("root")?.removeAttribute("inert");
}

type Placement = "top" | "center" | "right";

const PLACEMENT: Record<Placement, { wrapper: string; panel: string }> = {
  top: { wrapper: "items-start justify-center px-3 pt-[10vh]", panel: "w-full max-w-2xl" },
  center: { wrapper: "items-center justify-center px-3", panel: "w-full max-w-lg" },
  right: { wrapper: "items-stretch justify-end", panel: "h-full w-full max-w-md overflow-y-auto" },
};

interface OverlayProps {
  open: boolean;
  onClose: () => void;
  /** Names the dialog for assistive technology. */
  label: string;
  placement?: Placement;
  /** The element to focus when the overlay opens. Defaults to the first focusable element. */
  initialFocus?: RefObject<HTMLElement | null>;
  children: ReactNode;
}

/**
 * A modal dialog in a portal: focus moves in, is trapped while open and returns to where it was
 * when the overlay closes. Escape and a click on the backdrop close it.
 */
export default function Overlay({
  open,
  onClose,
  label,
  placement = "center",
  initialFocus,
  children,
}: OverlayProps) {
  const dialog = useRef<HTMLDivElement>(null);
  const closeRef = useRef(onClose);

  useEffect(() => {
    closeRef.current = onClose;
  }, [onClose]);

  useEffect(() => {
    if (!open) return;
    const id = Symbol("overlay");
    // Map markers are SVG elements, so an HTMLElement check alone would lose them.
    const active = document.activeElement;
    const opener = active instanceof HTMLElement || active instanceof SVGElement ? active : null;
    stack.push(id);
    lockPage();

    const first = dialog.current?.querySelector<HTMLElement>(FOCUSABLE);
    (initialFocus?.current ?? first ?? dialog.current)?.focus();

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && stack[stack.length - 1] === id) {
        event.preventDefault();
        closeRef.current();
      }
    };
    document.addEventListener("keydown", onKeyDown);

    return () => {
      document.removeEventListener("keydown", onKeyDown);
      stack.splice(stack.indexOf(id), 1);
      if (stack.length === 0) unlockPage();
      if (opener?.isConnected) opener.focus();
    };
  }, [open, initialFocus]);

  if (!open) return null;

  const trapTab = (event: React.KeyboardEvent<HTMLDivElement>) => {
    if (event.key !== "Tab") return;
    const nodes = Array.from(dialog.current?.querySelectorAll<HTMLElement>(FOCUSABLE) ?? []);
    const firstNode = nodes[0];
    const lastNode = nodes[nodes.length - 1];
    if (firstNode === undefined || lastNode === undefined) {
      event.preventDefault();
      return;
    }
    if (event.shiftKey && document.activeElement === firstNode) {
      event.preventDefault();
      lastNode.focus();
    } else if (!event.shiftKey && document.activeElement === lastNode) {
      event.preventDefault();
      firstNode.focus();
    }
  };

  const { wrapper, panel } = PLACEMENT[placement];
  return createPortal(
    <div
      className={`fixed inset-0 z-50 flex animate-fade bg-void/75 backdrop-blur-sm ${wrapper}`}
      onMouseDown={(event) => {
        if (event.target !== event.currentTarget) return;
        // Without this the browser moves focus to the page after the overlay has already given it
        // back to the opener, and the opener loses it again.
        event.preventDefault();
        onClose();
      }}
    >
      <div
        ref={dialog}
        role="dialog"
        aria-modal="true"
        aria-label={label}
        tabIndex={-1}
        onKeyDown={trapTab}
        className={`${panel} animate-rise focus:outline-none`}
      >
        {children}
      </div>
    </div>,
    document.body,
  );
}
