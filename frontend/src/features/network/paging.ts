/** How many alerts and flows one page lists. The API serves up to 200; a page this size stays readable. */
export const ALERTS_PAGE_SIZE = 25;
export const FLOWS_PAGE_SIZE = 25;
/** Sessions are listed in a smaller page, so the history leaves the selected session in view. */
export const SESSIONS_PAGE_SIZE = 5;
/** Public addresses are all in the session detail, so they are paged on this side. */
export const ADDRESSES_PAGE_SIZE = 10;
