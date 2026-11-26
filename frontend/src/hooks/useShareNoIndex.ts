import { useEffect } from "react";

/**
 * Asks search engines to leave the page out while it is open. A share link is handed to one
 * person, so it must never be listed. The tag is added on arrival and taken away on departure, so
 * the console's own pages are not affected.
 */
export function useShareNoIndex(): void {
  useEffect(() => {
    const meta = document.createElement("meta");
    meta.name = "robots";
    meta.content = "noindex,nofollow";
    document.head.append(meta);
    return () => meta.remove();
  }, []);
}
