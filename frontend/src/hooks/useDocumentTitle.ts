import { useEffect } from "react";

const BASE_TITLE = "CipherForge";

/** Names the page in the browser tab and history, which also tells screen readers where they are. */
export function useDocumentTitle(title: string): void {
  useEffect(() => {
    document.title = title ? `${title} · ${BASE_TITLE}` : BASE_TITLE;
  }, [title]);
}
