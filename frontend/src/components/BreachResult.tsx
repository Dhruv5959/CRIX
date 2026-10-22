import { SourceModeBadge, StatusBadge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { BreachLookupSummary } from "@/lib/breach";

// Renders one email-breach lookup. Everything shown comes from the server's
// normalized events (via `summarizeBreachLookup`) — nothing is inferred here, so
// a provider failure is displayed as UNKNOWN rather than as a clean result.
//
// Colour discipline (established in the redesign): accent carries the finding,
// emerald is reserved for a verified-clear, amber for unknown/unavailable.

const LEVEL_TONE: Record<string, string> = {
  HIGH: "border-rose-500/40 bg-rose-500/10 text-rose-300",
  MEDIUM: "border-amber-500/40 bg-amber-500/10 text-amber-300",
  LOW: "border-white/15 bg-white/[0.06] text-ink-muted",
  CLEAR: "border-emerald-500/40 bg-emerald-500/10 text-emerald-300",
  UNKNOWN: "border-amber-500/40 bg-amber-500/10 text-amber-300",
  NONE: "border-white/15 bg-white/[0.06] text-ink-faint",
};

export function BreachResult({ summary }: { summary: BreachLookupSummary }) {
  return (
    <div className="glass-sub space-y-3 rounded-lg p-4" data-testid="breach-result">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <StatusBadge status={summary.status} />
          <span
            className={cn(
              "inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide",
              LEVEL_TONE[summary.level] || LEVEL_TONE.NONE,
            )}
          >
            {summary.level === "NONE" ? "NO RESULT" : summary.level}
          </span>
        </div>
        {/* REAL only when a live provider actually answered. */}
        <SourceModeBadge mode={summary.hasVerdict ? "REAL" : "UNAVAILABLE"} />
      </div>

      <div>
        <div className="text-sm font-medium text-ink">{summary.headline}</div>
        <p className="mt-1 text-[11px] leading-relaxed text-ink-muted">{summary.detail}</p>
      </div>

      {summary.breaches.length > 0 && (
        <div className="flex flex-wrap gap-1.5" data-testid="breach-names">
          {summary.breaches.map((name) => (
            <span
              key={name}
              className="rounded border border-white/15 bg-white/[0.06] px-2 py-0.5 text-[10px] text-ink-muted"
            >
              {name}
            </span>
          ))}
          {summary.truncated && (
            <span className="rounded border border-white/15 px-2 py-0.5 text-[10px] text-ink-faint">
              +{Math.max(0, summary.breachCount - summary.breaches.length)} more
            </span>
          )}
        </div>
      )}

      {summary.reason && (
        <p className="rounded border border-amber-500/30 bg-amber-500/5 px-3 py-2 text-[11px] leading-relaxed text-amber-200">
          {summary.reason}
        </p>
      )}

      <div className="flex flex-wrap gap-x-5 gap-y-1 text-[11px] text-ink-faint">
        <span>
          Provider: <span className="text-ink-muted">{summary.providerLabel}</span>
        </span>
        <span>
          {summary.timeLabel}:{" "}
          <span className="font-mono text-ink-muted">{summary.timeText}</span>
        </span>
        <span>
          Signal strength:{" "}
          <span className="font-mono text-ink-muted">{summary.severity.toFixed(2)}</span>
        </span>
        <span>
          Confidence:{" "}
          <span className="font-mono text-ink-muted">{summary.confidence.toFixed(2)}</span>
        </span>
      </div>
    </div>
  );
}
