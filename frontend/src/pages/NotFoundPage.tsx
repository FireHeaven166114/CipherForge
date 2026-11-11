import { Link } from "react-router";

import { LINK } from "../components/styles";
import { useDocumentTitle } from "../hooks/useDocumentTitle";

export default function NotFoundPage() {
  useDocumentTitle("Page not found");
  return (
    <div className="space-y-3">
      <h1 className="text-2xl font-semibold tracking-tight">Page not found</h1>
      <p className="text-slate-300">There is nothing at this address.</p>
      <Link to="/" className={LINK}>
        Go to the overview
      </Link>
    </div>
  );
}
