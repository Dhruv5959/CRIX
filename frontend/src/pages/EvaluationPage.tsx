import { useEffect, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { AlertTriangle, BarChart3 } from "lucide-react";
import { api } from "@/lib/api";
import type { EvaluationSummary } from "@/lib/types";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/card";
import { ProvenanceBadge } from "@/components/ui/badge";
import { formatNumber, formatPercent } from "@/lib/utils";

const SUITE_LABELS: Record<string, string> = {
  phishing_classifier: "Phishing classifier",
  ai_text_detector: "AI-text detector",
  planner: "Remediation planner",
  shapley: "Exact Shapley",
  correlation: "Correlation engine",
};

function MetricRow({ label, value }: { label: string; value: number }) {
  const percent = ["f1", "precision", "recall", "accuracy", "scenario_pass_rate", "max_efficiency_error"].includes(label)
    ? formatPercent(value, 2)
    : undefined;
  const isSmall = Math.abs(value) < 0.01 && value !== 0;
  return (
    <div className="flex items-center justify-between border-b border-white/10 py-2 last:border-0">
      <span className="text-xs text-ink-muted">{label.replace(/_/g, " ")}</span>
      <span className="font-mono text-xs text-ink">
        {isSmall ? value.toExponential(2) : percent ?? formatNumber(value, 3)}
      </span>
    </div>
  );
}

function ConfusionMatrix({ matrix, labels }: { matrix: number[][]; labels: string[] }) {
  const max = Math.max(...matrix.flat(), 1);
  return (
    <div className="mt-3">
      <div className="label-eyebrow mb-2">Confusion matrix</div>
      <div className="inline-grid gap-1" style={{ gridTemplateColumns: `auto repeat(${labels.length}, 1fr)` }}>
        <div />
        {labels.map((l) => (
          <div key={l} className="text-center text-[10px] text-ink-faint">
            {l}
          </div>
        ))}
        {matrix.map((row, i) => (
          <div key={i} className="contents">
            <div className="pr-2 text-right text-[10px] text-ink-faint">{labels[i]}</div>
            {row.map((cell, j) => (
              <div
                key={j}
                className="grid h-10 w-16 place-items-center rounded border border-white/10 font-mono text-xs"
                style={{
                  background: i === j ? `rgba(34,211,238,${0.1 + 0.4 * (cell / max)})` : `rgba(244,63,94,${0.08 + 0.3 * (cell / max)})`,
                  color: i === j ? "#67e8f9" : "#fda4af",
                }}
              >
                {cell}
              </div>
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}

export default function EvaluationPage() {
  const [data, setData] = useState<EvaluationSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.evaluation().then(setData).catch((e) => setError(e.message));
  }, []);

  return (
    <div className="space-y-6 animate-fade-in">
      <header className="flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-ink">Evaluation</h1>
          <p className="mt-1 text-sm text-ink-muted">
            Every number here was produced by the evaluation harness actually running on test data.
            Unmeasured suites say so.
          </p>
        </div>
        <ProvenanceBadge provenance="MODEL" />
      </header>

      {error && (
        <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-300">{error}</div>
      )}

      {data && !data.measured && (
        <Card>
          <CardBody className="flex items-center gap-3">
            <AlertTriangle size={18} className="text-amber-300" />
            <div>
              <p className="text-sm text-ink">No measurements yet — "not yet measured".</p>
              <p className="text-xs text-ink-faint">
                Run <code className="kbd">backend/scripts/run_evaluation.py</code> to populate real metrics.
              </p>
            </div>
          </CardBody>
        </Card>
      )}

      {data &&
        Object.entries(data.suites).map(([suite, info]) => {
          const phishingMatrix = info.details["total_evaluated"] as { matrix?: number[][]; labels?: string[] } | undefined;
          const f1 = info.metrics["f1"];
          const maxError = info.metrics["max_efficiency_error"];
          const datasetNote =
            suite === "phishing_classifier" || suite === "ai_text_detector"
              ? "synthetic corpus (disjoint-template test split)"
              : undefined;
          return (
            <Card key={suite}>
              <CardHeader>
                <div className="flex items-center gap-2">
                  <BarChart3 size={15} className="text-accent" />
                  <CardTitle>{SUITE_LABELS[suite] || suite}</CardTitle>
                </div>
                <div className="flex items-center gap-2">
                  {datasetNote && (
                    <span className="rounded border border-amber-500/40 bg-amber-500/10 px-1.5 py-0.5 text-[10px] font-semibold uppercase text-amber-300">
                      synthetic data
                    </span>
                  )}
                  <ProvenanceBadge provenance="MODEL" />
                </div>
              </CardHeader>
              <CardBody className="grid grid-cols-1 gap-5 lg:grid-cols-2">
                <div>
                  {Object.entries(info.metrics)
                    .filter(([k]) => k !== "total_evaluated" && k !== "per_scenario")
                    .map(([k, v]) => (
                      <MetricRow key={k} label={k} value={v} />
                    ))}
                </div>
                {f1 !== undefined && (
                  <ResponsiveContainer width="100%" height={200}>
                    <BarChart
                      data={[
                        { name: "precision", value: info.metrics["precision"] },
                        { name: "recall", value: info.metrics["recall"] },
                        { name: "f1", value: info.metrics["f1"] },
                        { name: "accuracy", value: info.metrics["accuracy"] },
                      ]}
                    >
                      <CartesianGrid stroke="rgba(148,163,184,0.08)" vertical={false} />
                      <XAxis dataKey="name" stroke="#64748b" fontSize={11} />
                      <YAxis domain={[0, 1]} stroke="#64748b" fontSize={11} />
                      <Tooltip
                        contentStyle={{ background: "#0b1220", border: "1px solid #28354f", borderRadius: 10, fontSize: 12 }}
                        formatter={(v: number) => formatPercent(v, 1)}
                      />
                      <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                        {["precision", "recall", "f1", "accuracy"].map((n) => (
                          <Cell key={n} fill={n === "f1" ? "#22d3ee" : "#334155"} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                )}
                {maxError !== undefined && (
                  <div className="glass-sub rounded-lg p-3 text-xs text-ink-faint">
                    Exact Shapley efficiency error stays within{" "}
                    <span className="font-mono text-accent">{maxError.toExponential(1)}</span> — the
                    contributions sum to the total risk, confirming the efficiency property.
                  </div>
                )}
                {phishingMatrix?.matrix && phishingMatrix.labels && (
                  <ConfusionMatrix matrix={phishingMatrix.matrix} labels={phishingMatrix.labels} />
                )}
              </CardBody>
            </Card>
          );
        })}

      <p className="text-[11px] leading-relaxed text-ink-faint">{data?.note}</p>
    </div>
  );
}