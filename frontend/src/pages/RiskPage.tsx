import {
  Bar,
  BarChart,
  Cell,
  CartesianGrid,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { useAnalysis } from "@/lib/analysis";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/card";
import { RiskGauge } from "@/components/ui/risk-gauge";
import { ProvenanceBadge } from "@/components/ui/badge";
import { formatNumber } from "@/lib/utils";

export default function RiskPage() {
  const { result, loading } = useAnalysis();
  if (loading && !result) return <div className="text-sm text-ink-faint">Loading…</div>;
  if (!result) return null;

  const { risk, attribution, features } = result;
  const contributions = Object.entries(attribution.contributions)
    .filter(([, v]) => Math.abs(v) > 1e-6)
    .sort((a, b) => Math.abs(b[1]) - Math.abs(a[1]))
    .map(([name, value]) => ({ name: name.replace(/_/g, " "), feature: name, value: Number(value.toFixed(2)) }));

  const featureRows = Object.entries(features)
    .filter(([, v]) => v > 0)
    .sort((a, b) => b[1] - a[1]);

  return (
    <div className="space-y-6 animate-fade-in">
      <header>
        <h1 className="text-2xl font-semibold text-ink">Risk & Attribution</h1>
        <p className="mt-1 text-sm text-ink-muted">
          The contextual risk score and its transparent attribution via exact cooperative-game
          Shapley values over the deterministic risk function.
        </p>
      </header>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle>Contextual Risk</CardTitle>
            <ProvenanceBadge provenance="MODEL" />
          </CardHeader>
          <CardBody className="flex flex-col items-center gap-5">
            <RiskGauge score={risk.score} band={risk.band} rangeLow={risk.range_low} rangeHigh={risk.range_high} />
            <div className="grid w-full grid-cols-3 gap-2 text-center">
              <div>
                <div className="label-eyebrow">Base</div>
                <div className="font-mono text-sm text-ink">{formatNumber(risk.base_risk)}</div>
              </div>
              <div>
                <div className="label-eyebrow">Interaction</div>
                <div className="font-mono text-sm text-ink">+{formatNumber(risk.interaction_risk)}</div>
              </div>
              <div>
                <div className="label-eyebrow">Mitigation</div>
                <div className="font-mono text-sm text-ink">−{formatNumber(risk.mitigation_credit)}</div>
              </div>
            </div>
          </CardBody>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Shapley Attribution</CardTitle>
            <span className="text-[11px] text-ink-faint">
              {attribution.method} · {formatNumber(attribution.compute_ms, 1)} ms · efficiency error{" "}
              {attribution.efficiency_error.toExponential(1)}
            </span>
          </CardHeader>
          <CardBody>
            {contributions.length === 0 ? (
              <p className="text-sm text-ink-faint">No contributing factors.</p>
            ) : (
              <ResponsiveContainer width="100%" height={Math.max(220, contributions.length * 34)}>
                <BarChart data={contributions} layout="vertical" margin={{ left: 24, right: 24 }}>
                  <CartesianGrid horizontal={false} stroke="rgba(148,163,184,0.08)" />
                  <XAxis type="number" stroke="#64748b" fontSize={11} />
                  <YAxis type="category" dataKey="name" width={96} stroke="#64748b" fontSize={11} />
                  <ReferenceLine x={0} stroke="rgba(148,163,184,0.3)" />
                  <Tooltip
                    contentStyle={{
                      background: "#0b1220",
                      border: "1px solid #28354f",
                      borderRadius: 10,
                      fontSize: 12,
                    }}
                    formatter={(v: number) => [`${v >= 0 ? "+" : ""}${v.toFixed(2)}`, "contribution"]}
                  />
                  <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                    {contributions.map((entry) => (
                      <Cell key={entry.feature} fill={entry.value >= 0 ? "#22d3ee" : "#34d399"} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
            <p className="mt-3 text-[11px] leading-relaxed text-ink-faint">
              Contributions sum to the total risk (efficiency property):{" "}
              <span className="font-mono text-ink-muted">
                Σ = {formatNumber(attribution.sum_of_contributions, 4)} vs total{" "}
                {formatNumber(attribution.total_risk, 4)}
              </span>
              . Positive bars raise risk; negative bars (mitigations) lower it.
            </p>
          </CardBody>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Feature Vector</CardTitle>
          <span className="text-[11px] text-ink-faint">inputs to the risk function</span>
        </CardHeader>
        <CardBody>
          {featureRows.length === 0 ? (
            <p className="text-sm text-ink-faint">All features are zero.</p>
          ) : (
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
              {featureRows.map(([name, value]) => (
                <div key={name} className="glass-sub rounded-lg px-3 py-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-ink-muted">{name.replace(/_/g, " ")}</span>
                    <span className="font-mono text-xs text-ink">{value.toFixed(2)}</span>
                  </div>
                  <div className="mt-1.5 h-1 overflow-hidden rounded-full bg-white/10">
                    <div className="h-full rounded-full bg-accent/50" style={{ width: `${value * 100}%` }} />
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardBody>
      </Card>

      <p className="text-[11px] leading-relaxed text-ink-faint">
        The score is a relative prioritization, not a probability. The sensitivity range reflects a
        bounded perturbation of the inputs, not a statistical confidence interval.
      </p>
    </div>
  );
}