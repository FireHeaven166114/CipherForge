import { Link } from "react-router";

import PageHeader from "../components/hud/PageHeader";
import Panel from "../components/hud/Panel";
import { PRIMARY_BUTTON } from "../components/styles";
import { useDocumentTitle } from "../hooks/useDocumentTitle";

export default function NotFoundPage() {
  useDocumentTitle("Page not found");
  return (
    <div className="space-y-6">
      <PageHeader
        code="ERR-404 · SIGNAL LOST"
        title="Page not found"
        description="There is nothing at this address."
      />
      <Panel title="No route" code="404" bodyClassName="flex flex-wrap items-center gap-x-8 gap-y-4 p-6">
        <p aria-hidden="true" className="font-mono text-6xl font-semibold text-cipher/70">
          404
        </p>
        <div className="space-y-3">
          <p>The address may be mistyped, or the page may have moved.</p>
          <Link to="/" className={PRIMARY_BUTTON}>
            Go to the overview
          </Link>
        </div>
      </Panel>
    </div>
  );
}
