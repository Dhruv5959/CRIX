import { useEffect, useState } from "react";
import { History, TrendingDown, TrendingUp } from "lucide-react";
import { api } from "@/lib/api";
import type { RiskHistoryEntry } from "@/lib/types";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/card";
import { ProvenanceBadge } from "@/components/ui/badge";
import { cn, formatNumber } from "@/lib/utils";

export default function RiskHistoryPage() {
  const [entries, setEntries] = useState<RiskHistoryEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.riskHistory()
      .then((r) => setEntries(r.entries))
      .catch((e) => setError(e instanceof Error ? e.message : "Failed to load risk history"))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="text-sm text-ink-faint">Loading risk history…</div>;

  const sorted = [...entries].sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());

  return (
    <div className="space-y-6 animate-fade-in">
      <header>
        <h1 className="text-2xl font-semibold text-ink">Risk History</h1>
        <p className="mt-1 text-sm text-ink-muted">
          Historical risk score snapshots from analysis pipeline runs.
        </p>
      </header>

      {error && (
        <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-300">{error}</div>
      )}

      {/* Timeline chart (simple bar representation) */}
      {sorted.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle><History size={15} className="inline mr-1" /> Score Timeline</CardTitle>
            <ProvenanceBadge provenance="MODEL" />
          </CardHeader>
          <CardBody>
            <div className="space-y-2">
              {sorted.map((entry, i) => {
                const prev = sorted[i + 1];
                const delta = prev ? entry.score - prev.score : 0;
                return (
                  <div key={entry.id} className="flex items-center gap-3">
                    <div className="w-32 text-[11px] text-ink-faint shrink-0">
                      {new Date(entry.created_at).toLocaleDateString()}
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <div
                          className={cn(
                            "h-4 rounded-full",
                            entry.band === "CRITICAL" ? "bg-rose-500" :
                            entry.band === "HIGH" ? "bg-orange-500" :
                            entry.band === "MEDIUM" ? "bg-amber-500" :
                            "bg-emerald-500"
                          )}
                          style={{ width: `${Math.max(4, entry.score)}%` }}
                        />
                        <span className="font-mono text-xs text-ink">{formatNumber(entry.score)}</span>
                        <span className="text-[10px] text-ink-faint">{entry.band}</span>
                      </div>
                    </div>
                    <div className="w-16 text-right">
                      {delta !== 0 && (
                        <span className={cn("flex items-center justify-end gap-0.5 text-[11px]", delta > 0 ? "text-rose-300" : "text-emerald-300")}>
                          {delta > 0 ? <TrendingUp size={11} /> : <TrendingDown size={11} />}
                          {delta > 0 ? "+" : ""}{formatNumber(delta)}
                        </span>
                      )}
                    </div>
                    <div className="w-16 text-right font-mono text-[10px] text-ink-faint">
                      {entry.model_version}
                    </div>
                  </div>
                );
              })}
            </div>
          </CardBody>
        </Card>
      )}

      {sorted.length === 0 && !error && (
        <Card>
          <CardBody className="text-center text-sm text-ink-faint py-8">
            No risk history entries yet. Run the analysis pipeline to create snapshots.
          </CardBody>
        </Card>
      )}
    </div>
  );
}

