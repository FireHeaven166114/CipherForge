import { Route, Routes } from "react-router";

import Layout from "./components/Layout";
import FilesPage from "./pages/FilesPage";
import IndicatorDetailPage from "./pages/IndicatorDetailPage";
import IndicatorsPage from "./pages/IndicatorsPage";
import InvestigatePage from "./pages/InvestigatePage";
import NetworkPage from "./pages/NetworkPage";
import NotFoundPage from "./pages/NotFoundPage";
import OverviewPage from "./pages/OverviewPage";
import SharePage from "./pages/SharePage";
import StatusPage from "./pages/StatusPage";

/**
 * The router itself is supplied by the caller (BrowserRouter in main.tsx, MemoryRouter in tests).
 * Client routes must stay clear of /api, /health and /ready, which nginx proxies to the backend.
 */
export default function App() {
  return (
    <Routes>
      {/* A share link is opened by people who are not signed in, so its page sits outside the console. */}
      <Route path="share/:token" element={<SharePage />} />
      <Route element={<Layout />}>
        <Route index element={<OverviewPage />} />
        <Route path="investigate" element={<InvestigatePage />} />
        <Route path="indicators" element={<IndicatorsPage />} />
        <Route path="indicators/:indicatorId" element={<IndicatorDetailPage />} />
        <Route path="network" element={<NetworkPage />} />
        <Route path="files" element={<FilesPage />} />
        <Route path="status" element={<StatusPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  );
}
