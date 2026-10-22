import { useEffect, useState } from "react";
import { GitCompareArrows, Wand2 } from "lucide-react";
import { api } from "@/lib/api";
import { useAnalysis } from "@/lib/analysis";
import type { WhatIfResult } from "@/lib/types";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { ProvenanceBadge } from "@/components/ui/badge";
import { formatNumber, formatPercent } from "@/lib/utils";

interface ActionMeta {
  key: string;
  title: string;
  description: string;
  effort: number;
}

const WHATIF_ACTIONS = [
  { key: "strengthen_mfa", toggle: "strengthen_mfa", label: "Enable MFA" },
  { key: "change_reused_password", toggle: "change_reused_password", label: "Change reused password" },
  { key: "revoke_session", toggle: "revoke_session", label: "Revoke app / session" },
  { key: "enable_passkey", toggle: "enable_passkey", label: "Enable passkey" },
];

export default function RemediationPage() {
  const { result, loading, refresh } = useAnalysis();
  const [actions, setActions] = useState<ActionMeta[]>([]);
  const [toggles, setToggles] = useState<Record<string, boolean>>({});
  const [whatIf, setWhatIf] = useState<WhatIfResult | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.plannerActions().then((r) => setActions(r.actions as unknown as ActionMeta[])).catch(() => {});
  }, []);

  async function runWhatIf(next: Record<string, boolean>) {
    setBusy(true);
    try {
      const payload = Object.entries(next)
        .filter(([, enabled]) => enabled)
        .map(([action_key]) => ({ action_key, enabled: true }));
      setWhatIf(await api.whatIf(payload));
    } finally {
      setBusy(false);
    }
  }

  function toggle(key: string) {
    const next = { ...toggles, [key]: !toggles[key] };
    setToggles(next);
    runWhatIf(next);
  }

  if (loading && !result) return <div className="text-sm text-ink-faint">Loading…</div>;
  if (!result) return null;

  const comparison = result.planner;

  return (
    <div className="space-y-6 animate-fade-in">
      <header className="flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-ink">Remediation & What-If</h1>
          <p className="mt-1 text-sm text-ink-muted">
            Greedy baseline vs. exact branch-and-bound, plus a live simulator that re-runs the real
            risk + attribution pipeline.
          </p>
        </div>
        <Button variant="secondary" size="sm" onClick={refresh}>
          Refresh
        </Button>
      </header>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <PlanCard title="Greedy baseline" plan={comparison.greedy} tone="neutral" />
        <PlanCard title="Exact (branch-and-bound)" plan={comparison.exact} tone="accent" />
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <Card>
          <CardBody>
            <div className="label-eyebrow">Measured optimality gap</div>
            <div className="mt-1 font-mono text-2xl text-ink">
              {formatPercent(comparison.optimality_gap, 2)}
            </div>
            <p className="mt-1 text-[11px] text-ink-faint">
              relative shortfall of greedy vs. exact on this feature vector
            </p>
          </CardBody>
        </Card>
        <Card>
          <CardBody>
            <div className="label-eyebrow">Initial risk</div>
            <div className="mt-1 font-mono text-2xl text-ink">{formatNumber(comparison.initial_risk)}</div>
            <p className="mt-1 text-[11px] text-ink-faint">before remediation</p>
          </CardBody>
        </Card>
        <Card>
          <CardBody>
            <div className="label-eyebrow">Greedy trap</div>
            <div className="mt-1 font-mono text-2xl text-ink">
              {comparison.is_greedy_trap ? "DETECTED" : "no"}
            </div>
            <p className="mt-1 text-[11px] text-ink-faint">
              {comparison.is_greedy_trap
                ? "greedy did strictly worse than exact here"
                : "greedy matched exact on this vector"}
            </p>
          </CardBody>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Wand2 size={15} className="text-accent" />
            <CardTitle>What-If Simulator</CardTitle>
          </div>
          <ProvenanceBadge provenance="MODEL" />
        </CardHeader>
        <CardBody className="space-y-5">
          <p className="text-xs text-ink-faint">
            Toggle mitigations to re-run the <em>real</em> risk and attribution pipeline on a
            hypothetical copy of your input. Historical facts (e.g. a breach) do not disappear —
            only mitigation state changes.
          </p>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            {WHATIF_ACTIONS.map((a) => (
              <div key={a.key} className="glass-sub rounded-lg p-3">
                <Switch
                  checked={!!toggles[a.toggle]}
                  onChange={() => toggle(a.toggle)}
                  label={a.label}
                  disabled={busy}
                />
              </div>
            ))}
          </div>

          {whatIf && (
            <div className="grid grid-cols-1 gap-4 rounded-lg border border-accent/30 bg-accent/5 p-4 sm:grid-cols-3">
              <div>
                <div className="label-eyebrow">Before</div>
                <div className="font-mono text-2xl text-ink-muted">{whatIf.before.score.toFixed(0)}</div>
                <div className="text-[11px] text-ink-faint">{whatIf.before.band}</div>
              </div>
              <div>
                <div className="label-eyebrow">After</div>
                <div className="font-mono text-2xl text-accent">{whatIf.after.score.toFixed(0)}</div>
                <div className="text-[11px] text-ink-faint">
                  {whatIf.after.band} · range {whatIf.after.range_low.toFixed(0)}–
                  {whatIf.after.range_high.toFixed(0)}
                </div>
              </div>
              <div>
                <div className="label-eyebrow">Reduction</div>
                <div className="font-mono text-2xl text-emerald-300">−{whatIf.delta.toFixed(0)}</div>
                <div className="text-[11px] text-ink-faint">
                  applied: {whatIf.applied_actions.length || "none"}
                </div>
              </div>
            </div>
          )}
        </CardBody>
      </Card>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <GitCompareArrows size={15} className="text-accent" />
            <CardTitle>Available actions</CardTitle>
          </div>
          <span className="text-[11px] text-ink-faint">effort = documented relative units</span>
        </CardHeader>
        <CardBody className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          {actions.map((a) => (
            <div key={a.key} className="glass-sub rounded-lg p-3">
              <div className="flex items-center justify-between">
                <span className="text-sm text-ink">{a.title}</span>
                <span className="glass-chip rounded border px-1.5 py-0.5 font-mono text-[10px] text-ink-faint">
                  effort {a.effort}
                </span>
              </div>
              <p className="mt-1 text-[11px] text-ink-faint">{a.description}</p>
            </div>
          ))}
        </CardBody>
      </Card>
    </div>
  );
}

function PlanCard({ title, plan, tone }: { title: string; plan: { actions: string[]; total_effort: number; risk_after: number; risk_reduction: number; compute_ms: number }; tone: "accent" | "neutral" }) {
  return (
    <Card className={tone === "accent" ? "border-accent/30" : ""}>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        {tone === "accent" && (
          <span className="rounded border border-accent/40 bg-accent/10 px-1.5 py-0.5 text-[10px] font-semibold uppercase text-accent">
            optimal
          </span>
        )}
      </CardHeader>
      <CardBody className="space-y-3">
        <div className="grid grid-cols-3 gap-2">
          <div>
            <div className="label-eyebrow">Risk after</div>
            <div className="font-mono text-lg text-ink">{plan.risk_after.toFixed(1)}</div>
          </div>
          <div>
            <div className="label-eyebrow">Reduction</div>
            <div className="font-mono text-lg text-emerald-300">−{plan.risk_reduction.toFixed(1)}</div>
          </div>
          <div>
            <div className="label-eyebrow">Effort</div>
            <div className="font-mono text-lg text-ink">{plan.total_effort.toFixed(0)}</div>
          </div>
        </div>
        <div className="flex flex-wrap gap-1.5">
          {plan.actions.length === 0 && <span className="text-xs text-ink-faint">no actions selected</span>}
          {plan.actions.map((a) => (
            <span key={a} className="rounded border border-white/15 bg-white/[0.06] px-2 py-0.5 text-[11px] text-ink-muted">
              {a.replace(/_/g, " ")}
            </span>
          ))}
        </div>
        <div className="text-[10px] text-ink-faint">solved in {plan.compute_ms.toFixed(2)} ms</div>
      </CardBody>
    </Card>
  );
}