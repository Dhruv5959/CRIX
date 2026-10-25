import { Suspense, lazy } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { useAuth } from "@/lib/auth";
import { AnalysisProvider } from "@/lib/analysis";
import Layout from "@/components/Layout";
import LoginPage from "@/pages/LoginPage";
import ResetPasswordPage from "@/pages/ResetPasswordPage";
import VerifyEmailPage from "@/pages/VerifyEmailPage";
import InviteAcceptPage from "@/pages/InviteAcceptPage";
import OverviewPage from "@/pages/OverviewPage";
import SignalsPage from "@/pages/SignalsPage";
import CorrelationsPage from "@/pages/CorrelationsPage";
import ExplanationPage from "@/pages/ExplanationPage";
import AssetsPage from "@/pages/AssetsPage";
import MembersPage from "@/pages/MembersPage";
import TasksPage from "@/pages/TasksPage";
import RiskHistoryPage from "@/pages/RiskHistoryPage";
import AuditPage from "@/pages/AuditPage";

// Heavy pages (force-graph, charting libraries) are split out of the initial
// bundle and loaded on demand.
const RiskPage = lazy(() => import("@/pages/RiskPage"));
const GraphPage = lazy(() => import("@/pages/GraphPage"));
const RemediationPage = lazy(() => import("@/pages/RemediationPage"));
const EvaluationPage = lazy(() => import("@/pages/EvaluationPage"));
const KnowledgePage = lazy(() => import("@/pages/KnowledgePage"));
const PropagationPage = lazy(() => import("@/pages/PropagationPage"));

function Protected({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  if (loading) {
    return (
      <div className="grid min-h-screen place-items-center text-sm text-ink-faint">Loading…</div>
    );
  }
  if (!user) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      {/* Target of the link in the password-reset email. */}
      <Route path="/reset-password" element={<ResetPasswordPage />} />
      {/* Target of the link in the email-verification email. */}
      <Route path="/verify-email" element={<VerifyEmailPage />} />
      {/* Target of the link in a member invitation email. */}
      <Route path="/invite" element={<InviteAcceptPage />} />
      <Route
        element={
          <Protected>
            <AnalysisProvider>
              <Layout />
            </AnalysisProvider>
          </Protected>
        }
      >
        <Route path="/" element={<OverviewPage />} />
        <Route path="/assets" element={<AssetsPage />} />
        <Route path="/members" element={<MembersPage />} />
        <Route path="/signals" element={<SignalsPage />} />
        <Route
          path="/propagation"
          element={
            <Suspense fallback={<PageFallback />}>
              <PropagationPage />
            </Suspense>
          }
        />
        <Route path="/correlations" element={<CorrelationsPage />} />
        <Route
          path="/risk"
          element={
            <Suspense fallback={<PageFallback />}>
              <RiskPage />
            </Suspense>
          }
        />
        <Route path="/risk-history" element={<RiskHistoryPage />} />
        <Route
          path="/graph"
          element={
            <Suspense fallback={<PageFallback />}>
              <GraphPage />
            </Suspense>
          }
        />
        <Route path="/tasks" element={<TasksPage />} />
        <Route
          path="/remediation"
          element={
            <Suspense fallback={<PageFallback />}>
              <RemediationPage />
            </Suspense>
          }
        />
        <Route path="/explanation" element={<ExplanationPage />} />
        <Route
          path="/evaluation"
          element={
            <Suspense fallback={<PageFallback />}>
              <EvaluationPage />
            </Suspense>
          }
        />
        <Route
          path="/knowledge"
          element={
            <Suspense fallback={<PageFallback />}>
              <KnowledgePage />
            </Suspense>
          }
        />
        <Route path="/audit" element={<AuditPage />} />
      </Route>
    </Routes>
  );
}

function PageFallback() {
  return <div className="py-16 text-center text-sm text-ink-faint">Loading…</div>;
}
