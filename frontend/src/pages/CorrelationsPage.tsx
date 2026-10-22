import { useAnalysis } from "@/lib/analysis";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/card";
import { ProvenanceBadge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

export default function CorrelationsPage() {
  const { result, loading } = useAnalysis();
  if (loading && !result) return <div className="text-sm text-ink-faint">Loading…</div>;
  if (!result) return null;

  return (
    <div className="space-y-6 animate-fade-in">
      <header>
        <h1 className="text-2xl font-semibold text-ink">Correlations</h1>
        <p className="mt-1 text-sm text-ink-muted">
          Declarative rules combine independent signals into one path. Rules are data
          (<code className="kbd">correlation_rules.yaml</code>), not hardcoded conditionals.
        </p>
      </header>

      {result.correlations.length === 0 && (
        <Card>
          <CardBody className="text-sm text-ink-faint">
            No correlations fired for the current signals. This means no <em>known multi-signal
            path</em> was detected — it is not a guarantee of safety.
          </CardBody>
        </Card>
      )}

      <div className="grid grid-cols-1 gap-4">
        {result.correlations.map((c) => (
          <Card key={c.correlation_id}>
            <CardHeader>
              <div className="flex items-center gap-3">
                <CardTitle>{c.title}</CardTitle>
                <span className="glass-chip rounded border px-1.5 py-0.5 font-mono text-[10px] text-ink-faint">
                  {c.rule_id} v{c.rule_version}
                </span>
              </div>
              <div className="flex items-center gap-3">
                <div className="text-right">
                  <div className="label-eyebrow">Severity</div>
                  <div className="font-mono text-sm text-accent">{c.severity.toFixed(2)}</div>
                </div>
                <div className="text-right">
                  <div className="label-eyebrow">Confidence</div>
                  <div className="font-mono text-sm text-ink-muted">{c.confidence.toFixed(2)}</div>
                </div>
              </div>
            </CardHeader>
            <CardBody className="space-y-4">
              <p className="text-sm leading-relaxed text-ink-muted">{c.explanation}</p>

              {c.chain?.length > 0 && (
                <div>
                  <div className="label-eyebrow mb-2">How this was combined</div>
                  <ol className="space-y-1.5 border-l border-white/10 pl-3">
                    {c.chain.map((step, i) => (
                      <li key={i} className="text-[12px] leading-relaxed text-ink-muted">
                        {step}
                      </li>
                    ))}
                  </ol>
                </div>
              )}

              {c.asset_ids?.length > 0 && (
                <div>
                  <div className="label-eyebrow mb-2">Company assets involved</div>
                  <div className="flex flex-wrap gap-1.5">
                    {c.asset_ids.map((id) => (
                      <span
                        key={id}
                        className="rounded border border-white/15 bg-white/[0.06] px-2 py-0.5 font-mono text-[11px] text-ink-muted"
                      >
                        {id}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              <div>
                <div className="label-eyebrow mb-2">Contributing findings</div>
                <div className="flex flex-wrap gap-1.5">
                  {result.events
                    .filter((e) => c.finding_ids.includes(e.event_id))
                    .map((e) => (
                      <span
                        key={e.event_id}
                        className={cn(
                          "rounded border px-2 py-0.5 text-[11px]",
                          "border-white/15 bg-white/[0.06] text-ink-muted",
                        )}
                      >
                        {e.event_type}
                        <span className="ml-1.5 text-ink-faint">sev {e.severity.toFixed(2)}</span>
                      </span>
                    ))}
                </div>
              </div>

              {c.uncertainty?.note && (
                <p className="text-[11px] leading-relaxed text-ink-faint">{c.uncertainty.note}</p>
              )}
            </CardBody>
          </Card>
        ))}
      </div>

      <div className="flex items-center gap-2 text-[11px] text-ink-faint">
        <ProvenanceBadge provenance="MODEL" /> Correlation severities are computed server-side and
        cannot be set by the client.
      </div>
    </div>
  );
}