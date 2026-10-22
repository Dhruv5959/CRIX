import { Link } from "react-router-dom";
import { ArrowUpRight, Info, RefreshCw } from "lucide-react";
import { useAnalysis } from "@/lib/analysis";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ProvenanceBadge } from "@/components/ui/badge";
import { RiskGauge } from "@/components/ui/risk-gauge";
import { formatNumber } from "@/lib/utils";

function Metric({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div>
      <div className="label-eyebrow">{label}</div>
      <div className="mt-1 font-mono text-xl text-ink">{value}</div>
      {hint && <div className="mt-0.5 text-[11px] text-ink-faint">{hint}</div>}
    </div>
  );
}

export default function OverviewPage() {
  const { result, loading, error, refresh } = useAnalysis();

  if (loading && !result) {
    return <div className="text-sm text-ink-faint">Running the CRIX pipeline…</div>;
  }
  if (error) {
    return <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-300">{error}</div>;
  }
  if (!result) return null;

  const { risk, correlations, attribution } = result;
  const topContributors = Object.entries(attribution.contributions)
    .filter(([, v]) => Math.abs(v) > 0.001)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);
  const findings = result.events.filter((e) => e.status === "FINDING");
  const unavailable = result.events.filter((e) => e.status === "UNAVAILABLE");

  return (
    <div className="space-y-6 animate-fade-in">
      <header className="flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-ink">Overview</h1>
          <p className="mt-1 text-sm text-ink-muted">
            A contextual risk score built from connected signals, with transparent attribution.
          </p>
        </div>
        <Button variant="secondary" size="sm" onClick={refresh} disabled={loading}>
          <RefreshCw size={14} className={loading ? "animate-spin" : ""} /> Re-run pipeline
        </Button>
      </header>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-1">
          <CardHeader>
            <CardTitle>Contextual Risk</CardTitle>
            <ProvenanceBadge provenance="MODEL" />
          </CardHeader>
          <CardBody className="flex flex-col items-center gap-4">
            <RiskGauge score={risk.score} band={risk.band} rangeLow={risk.range_low} rangeHigh={risk.range_high} />
            <p className="text-center text-xs leading-relaxed text-ink-faint">
              Relative prioritization, not a probability. Confidence:{" "}
              <span className="text-ink-muted">{risk.confidence}</span>.
            </p>
          </CardBody>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Score Composition</CardTitle>
            <span className="text-[11px] text-ink-faint">risk = base + interaction − mitigation</span>
          </CardHeader>
          <CardBody className="grid grid-cols-2 gap-5 sm:grid-cols-4">
            <Metric label="Base risk" value={formatNumber(risk.base_risk)} hint="sum of signal weights" />
            <Metric label="Interaction" value={`+${formatNumber(risk.interaction_risk)}`} hint="non-additive compounding" />
            <Metric label="Mitigation credit" value={`−${formatNumber(risk.mitigation_credit)}`} hint="controls in place" />
            <Metric label="Findings" value={`${findings.length}`} hint={`${unavailable.length} unavailable`} />
          </CardBody>
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Top Correlations</CardTitle>
            <Link to="/correlations" className="flex items-center gap-1 text-xs text-accent hover:underline">
              All <ArrowUpRight size={12} />
            </Link>
          </CardHeader>
          <CardBody className="space-y-3">
            {correlations.length === 0 && (
              <p className="text-sm text-ink-faint">
                No correlations fired. This means no multi-signal paths were detected — it does
                not guarantee safety.
              </p>
            )}
            {correlations.slice(0, 4).map((c) => (
              <div key={c.correlation_id} className="glass-sub rounded-lg p-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium text-ink">{c.title}</span>
                  <span className="font-mono text-xs text-accent">{c.severity.toFixed(2)}</span>
                </div>
                <p className="mt-1 line-clamp-2 text-xs text-ink-faint">{c.explanation}</p>
              </div>
            ))}
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Top Attribution (exact Shapley)</CardTitle>
            <span className="text-[11px] text-ink-faint">{formatNumber(attribution.compute_ms, 1)} ms</span>
          </CardHeader>
          <CardBody className="space-y-3">
            {topContributors.length === 0 && (
              <p className="text-sm text-ink-faint">No contributing factors yet.</p>
            )}
            {topContributors.map(([feature, value]) => (
              <div key={feature}>
                <div className="flex items-center justify-between text-xs">
                  <span className="text-ink-muted">{feature.replace(/_/g, " ")}</span>
                  <span className={`font-mono ${value >= 0 ? "text-accent" : "text-emerald-300"}`}>
                    {value >= 0 ? "+" : ""}
                    {value.toFixed(1)}
                  </span>
                </div>
                <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-white/10">
                  <div
                    className={`h-full rounded-full ${value >= 0 ? "bg-accent/60" : "bg-emerald-400/60"}`}
                    style={{ width: `${Math.min(100, Math.abs(value) * 2)}%` }}
                  />
                </div>
              </div>
            ))}
          </CardBody>
        </Card>
      </div>

      <div className="flex items-start gap-3 glass-sub rounded-lg p-4">
        <Info size={16} className="mt-0.5 shrink-0 text-accent" />
        <p className="text-xs leading-relaxed text-ink-faint">
          CRIX does not tell you what <em>will</em> happen. It correlates what is <em>known</em>, ranks
          relative risk, attributes it transparently, and orders what to fix first. Signals are
          labeled by provenance: <ProvenanceBadge provenance="REAL" /> from a live breach
          provider,{" "}
          <ProvenanceBadge provenance="SIMULATED" /> for scenarios you construct, and{" "}
          <ProvenanceBadge provenance="UNAVAILABLE" /> when a check could not run.
        </p>
      </div>
    </div>
  );
}