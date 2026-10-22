import { useCallback, useEffect, useState } from "react";
import { AlertTriangle, Play, Share2, ShieldAlert } from "lucide-react";
import { api, ApiError } from "@/lib/api";
import type { PropagationAccount, SimulationResult } from "@/lib/types";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Label, Select } from "@/components/ui/input";
import { SourceModeBadge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

const bandColor: Record<string, string> = {
  COMPROMISED: "border-rose-500/50 bg-rose-500/15 text-rose-200",
  HIGH: "border-rose-500/40 bg-rose-500/10 text-rose-300",
  MODERATE: "border-amber-500/40 bg-amber-500/10 text-amber-300",
  LOW: "border-emerald-500/40 bg-emerald-500/10 text-emerald-300",
};

// Compromise Propagation Analysis: a defensive what-if. Selecting an account
// here never touches, disables, or messages a real account — it recomputes the
// dependency graph, contextual risk, Shapley attribution, and remediation.
export default function PropagationPage() {
  const [accounts, setAccounts] = useState<PropagationAccount[]>([]);
  const [selected, setSelected] = useState("");
  const [result, setResult] = useState<SimulationResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    const res = await api.propagationAccounts();
    setAccounts(res.accounts);
    setSelected((prev) => prev || (res.accounts[0]?.account_id ?? ""));
  }, []);

  useEffect(() => {
    load().catch(() => setError("Could not load accounts."));
  }, [load]);

  async function run() {
    if (!selected) return;
    setBusy(true);
    setError(null);
    try {
      setResult(await api.simulateCompromise(selected));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Simulation failed.");
      setResult(null);
    } finally {
      setBusy(false);
    }
  }

  const prop = result?.propagation;

  return (
    <div className="space-y-6 animate-fade-in">
      <header>
        <h1 className="text-2xl font-semibold text-ink">Compromise Propagation Analysis</h1>
        <p className="mt-1 max-w-3xl text-sm text-ink-muted">
          A defensive what-if. CRIX does not hack, access, alter, disable, or send anything on any
          account. It recomputes how exposure would travel through{" "}
          <em>your confirmed</em> account-dependency graph, then re-runs the real risk engine,
          Shapley attribution, and remediation planner.
        </p>
      </header>

      <Card>
        <CardHeader>
          <CardTitle>Simulate account compromise</CardTitle>
          <SourceModeBadge mode="SIMULATED" />
        </CardHeader>
        <CardBody className="space-y-4">
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-[1fr_auto] sm:items-end">
            <div>
              <Label>Account to treat as compromised (scenario only)</Label>
              <Select value={selected} onChange={(e) => setSelected(e.target.value)}>
                <option value="">Select an account…</option>
                {accounts.map((a) => (
                  <option key={a.account_id} value={a.account_id}>
                    {a.label} — {a.downstream_count} downstream
                  </option>
                ))}
              </Select>
            </div>
            <Button variant="primary" onClick={run} disabled={busy || !selected}>
              <Play size={14} /> {busy ? "Simulating…" : "Simulate Account Compromise"}
            </Button>
          </div>

          <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 px-3 py-2 text-[11px] leading-relaxed text-amber-200">
            SIMULATED scenario — no real account is touched, no control is disabled, no message is
            sent, no other account is accessed. Results are a relative prioritization, never a
            prediction that any account will be compromised.
          </div>

          {error && (
            <div className="flex items-start gap-2 rounded-lg border border-rose-500/30 bg-rose-500/5 px-4 py-3 text-sm text-rose-200">
              <AlertTriangle size={15} className="mt-0.5 shrink-0" />
              <span>{error}</span>
            </div>
          )}
        </CardBody>
      </Card>

      {result && prop && (
        <>
          {/* -------------------------------------------------------------- */}
          {/* Storyline                                                      */}
          {/* -------------------------------------------------------------- */}
          <Card>
            <CardHeader>
              <CardTitle>Potential compromise chain</CardTitle>
              <SourceModeBadge mode={result.scenario.source_mode} />
            </CardHeader>
            <CardBody className="space-y-3">
              <div className="glass-sub rounded-lg px-3 py-2 text-[11px] text-ink-muted">
                {result.scenario.notice}
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <span
                  className={cn(
                    "rounded border px-2 py-1 text-xs font-semibold uppercase",
                    bandColor.COMPROMISED,
                  )}
                >
                  {result.scenario.upstream_label} · COMPROMISED
                </span>
                <Share2 size={14} className="text-ink-faint" />
                <span className="text-[11px] text-ink-faint">
                  {prop.affected_count} downstream account{prop.affected_count === 1 ? "" : "s"}
                </span>
              </div>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                {result.storyline
                  .filter((n) => !n.is_upstream)
                  .map((n) => (
                    <div
                      key={n.account_id}
                      className="flex items-center gap-2 glass-sub rounded-lg px-3 py-2 text-xs"
                    >
                      <span className="text-ink-faint">↳</span>
                      <span className="flex-1 truncate text-ink">{n.label}</span>
                      {typeof n.path_length === "number" && n.path_length > 0 && (
                        <span className="font-mono text-[10px] text-ink-faint">
                          {n.path_length} hop{n.path_length === 1 ? "" : "s"}
                        </span>
                      )}
                      <SourceModeBadge mode={n.source_mode} />
                      <span
                        className={cn(
                          "rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase",
                          bandColor[n.band] || bandColor.LOW,
                        )}
                      >
                        {n.band}
                      </span>
                    </div>
                  ))}
              </div>
              <p className="text-[11px] leading-relaxed text-ink-faint">{result.disclaimer}</p>
            </CardBody>
          </Card>

          {/* -------------------------------------------------------------- */}
          {/* Downstream exposure                                            */}
          {/* -------------------------------------------------------------- */}
          <Card>
            <CardHeader>
              <CardTitle>Downstream exposure</CardTitle>
              <span className="text-[11px] text-ink-faint">highest band: {prop.overall_band}</span>
            </CardHeader>
            <CardBody className="space-y-4">
              <div className="glass-sub rounded-lg p-3 font-mono text-[11px] leading-relaxed text-ink-muted">
                {prop.formula}
              </div>

              {prop.downstream.length === 0 && (
                <p className="text-sm text-ink-faint">
                  No confirmed path leads out of this account. CRIX will not invent one.
                </p>
              )}

              <div className="space-y-3">
                {prop.downstream.map((d) => (
                  <div
                    key={d.account_id}
                    className="glass-sub rounded-lg p-3"
                  >
                    <div className="flex flex-wrap items-center gap-2 text-sm">
                      <span className="font-medium text-ink">{d.label}</span>
                      <span className="text-[11px] text-ink-faint">{d.provider}</span>
                      <div className="ml-auto flex items-center gap-2">
                        <SourceModeBadge mode={d.source_mode} />
                        <span
                          className={cn(
                            "rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase",
                            bandColor[d.band] || bandColor.LOW,
                          )}
                        >
                          {d.band}
                        </span>
                        <span className="font-mono text-xs text-ink">{d.exposure.toFixed(1)}</span>
                      </div>
                    </div>

                    <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-white/10">
                      <div
                        className={cn(
                          "h-full rounded-full",
                          d.band === "HIGH"
                            ? "bg-rose-400"
                            : d.band === "MODERATE"
                              ? "bg-amber-400"
                              : "bg-emerald-400",
                        )}
                        style={{ width: `${Math.max(2, Math.min(100, d.exposure))}%` }}
                      />
                    </div>

                    <div className="mt-2 grid grid-cols-2 gap-x-4 gap-y-1 text-[11px] sm:grid-cols-5">
                      {(
                        [
                          ["dependency", d.components.dependency_strength],
                          ["criticality", d.components.account_criticality],
                          ["weakness", d.components.credential_auth_weakness],
                          ["path exposure", d.components.path_exposure],
                          ["mitigation", d.components.mitigation_credit],
                        ] as Array<[string, number]>
                      ).map(([name, value]) => (
                        <div key={name}>
                          <div className="text-ink-faint">{name}</div>
                          <div
                            className={cn(
                              "font-mono",
                              name === "weakness" && d.components.weakness_unknown
                                ? "text-amber-300"
                                : "text-ink-muted",
                            )}
                          >
                            {value.toFixed(3)}
                            {name === "weakness" && d.components.weakness_unknown ? " ?" : ""}
                          </div>
                        </div>
                      ))}
                    </div>

                    {d.components.weakness_unknown && (
                      <p className="mt-2 text-[11px] text-amber-200">
                        No auth telemetry for this account — strength is <em>unknown</em>, scored at
                        a neutral default rather than treated as safe.
                      </p>
                    )}

                    <ul className="mt-2 space-y-0.5">
                      {d.reasons.map((r) => (
                        <li key={r} className="text-[11px] text-ink-faint">
                          · {r}
                        </li>
                      ))}
                    </ul>
                  </div>
                ))}
              </div>

              {prop.highest_risk_account_label && (
                <div className="flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/5 px-3 py-2 text-xs text-amber-200">
                  <ShieldAlert size={14} className="mt-0.5 shrink-0" />
                  <span>
                    <strong>{prop.highest_risk_account_label}</strong> has elevated downstream
                    compromise exposure if {prop.upstream_label} is compromised. This is a relative
                    exposure ranking under the scenario — not a statement that it will be hacked.
                  </span>
                </div>
              )}
            </CardBody>
          </Card>

          {/* -------------------------------------------------------------- */}
          {/* Recomputed risk + attribution                                  */}
          {/* -------------------------------------------------------------- */}
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>Recomputed contextual risk</CardTitle>
                <SourceModeBadge mode="SIMULATED" />
              </CardHeader>
              <CardBody className="space-y-4">
                <div className="flex items-baseline gap-3">
                  <span className="font-mono text-3xl text-ink">
                    {result.scenario_risk.score.toFixed(1)}
                  </span>
                  <span
                    className={cn(
                      "rounded border px-2 py-0.5 text-xs font-semibold uppercase",
                      bandColor[
                        result.scenario_risk.band === "HIGH"
                          ? "HIGH"
                          : result.scenario_risk.band === "MODERATE"
                            ? "MODERATE"
                            : "LOW"
                      ] || bandColor.LOW,
                    )}
                  >
                    {result.scenario_risk.band}
                  </span>
                </div>
                <div className="text-[11px] text-ink-faint">
                  range {result.scenario_risk.range_low.toFixed(1)} –{" "}
                  {result.scenario_risk.range_high.toFixed(1)} (sensitivity)
                </div>
                <div className="space-y-1.5 text-xs">
                  {(
                    [
                      ["base risk", result.scenario_risk.base_risk],
                      ["interaction risk", result.scenario_risk.interaction_risk],
                      [
                        "asset criticality",
                        result.scenario_risk.criticality_adjustment ?? 0,
                      ],
                      ["mitigation credit", -result.scenario_risk.mitigation_credit],
                    ] as Array<[string, number]>
                  ).map(([name, value]) => (
                    <div key={name} className="flex items-center justify-between">
                      <span className="text-ink-muted">{name}</span>
                      <span className="font-mono text-ink">{value.toFixed(2)}</span>
                    </div>
                  ))}
                </div>
                <p className="text-[11px] leading-relaxed text-ink-faint">
                  Recomputed by the deterministic CRIX risk engine with the scenario applied —
                  same 12-feature vector, same Shapley attribution.
                </p>
              </CardBody>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Scenario attribution</CardTitle>
                <span className="text-[11px] text-ink-faint">exact Shapley</span>
              </CardHeader>
              <CardBody className="space-y-2">
                {Object.entries(result.scenario_attribution.contributions)
                  .sort((a, b) => Math.abs(b[1]) - Math.abs(a[1]))
                  .slice(0, 8)
                  .map(([feature, value]) => {
                    const maxAbs = Math.max(
                      1e-9,
                      ...Object.values(result.scenario_attribution.contributions).map(Math.abs),
                    );
                    return (
                      <div key={feature} className="flex items-center gap-3 text-xs">
                        <span className="w-36 shrink-0 text-ink-muted">{feature}</span>
                        <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-white/10">
                          <div
                            className="h-full rounded-full bg-accent"
                            style={{
                              width: `${Math.max(2, (Math.abs(value) / maxAbs) * 100)}%`,
                            }}
                          />
                        </div>
                        <span className="w-14 shrink-0 text-right font-mono text-ink-faint">
                          {value.toFixed(3)}
                        </span>
                      </div>
                    );
                  })}
                <p className="pt-2 text-[11px] leading-relaxed text-ink-faint">
                  Attribution over the real CRIX risk function — not a trained surrogate. Efficiency
                  error {result.scenario_attribution.efficiency_error.toExponential(1)}.
                </p>
              </CardBody>
            </Card>
          </div>

          {/* -------------------------------------------------------------- */}
          {/* Remediation priority under the scenario                        */}
          {/* -------------------------------------------------------------- */}
          <Card>
            <CardHeader>
              <CardTitle>What to fix first, under this scenario</CardTitle>
              <span className="text-[11px] text-ink-faint">
                greedy baseline vs. exact · budget {result.scenario_plan.budget}
              </span>
            </CardHeader>
            <CardBody className="space-y-4">
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                {(
                  [
                    ["Baseline (no scenario)", result.scenario_plan.base_comparison],
                    ["Under simulated compromise", result.scenario_plan.comparison],
                  ] as Array<[string, typeof result.scenario_plan.comparison]>
                ).map(([title, cmp]) => (
                  <div
                    key={title}
                    className="glass-sub rounded-lg p-3"
                  >
                    <div className="text-[11px] uppercase tracking-wide text-ink-faint">{title}</div>
                    <div className="mt-2 flex items-baseline gap-2">
                      <span className="font-mono text-lg text-ink">
                        {cmp.initial_risk.toFixed(1)} → {cmp.exact.risk_after.toFixed(1)}
                      </span>
                      <span className="text-[11px] text-ink-faint">exact plan</span>
                    </div>
                    <div className="mt-1 text-[11px] text-ink-faint">
                      greedy {cmp.greedy.risk_after.toFixed(1)} · gap{" "}
                      {(cmp.optimality_gap * 100).toFixed(1)}%
                      {cmp.is_greedy_trap && (
                        <span className="ml-1 text-amber-300">(greedy trap)</span>
                      )}
                    </div>
                    <ol className="mt-2 space-y-0.5">
                      {cmp.exact.actions.map((action, i) => (
                        <li key={`${title}-${action}`} className="text-[11px] text-ink-muted">
                          {i + 1}. {action.replace(/_/g, " ")}
                        </li>
                      ))}
                    </ol>
                  </div>
                ))}
              </div>
              <p className="text-[11px] leading-relaxed text-ink-faint">
                {result.scenario_plan.note}
              </p>
            </CardBody>
          </Card>
        </>
      )}

      {!result && !error && (
        <Card>
          <CardBody className="py-10 text-center text-sm text-ink-faint">
            Connect accounts, confirm how they relate, then run a simulation to see how exposure
            would travel through your dependency graph.
          </CardBody>
        </Card>
      )}
    </div>
  );
}
