import type { HTMLAttributes } from "react";
import { cn } from "@/lib/utils";

// Deliberate, honest provenance labeling (§12): every screen must distinguish
// REAL / DEMO-SIMULATED / UNAVAILABLE data. These badges are used everywhere a
// datum's origin matters and are intentionally NOT decorative.

const styles: Record<string, string> = {
  REAL: "border-emerald-500/40 bg-emerald-500/10 text-emerald-300",
  USER_REPORTED: "border-sky-500/40 bg-sky-500/10 text-sky-300",
  SIMULATED: "border-amber-500/40 bg-amber-500/10 text-amber-300",
  CURATED: "border-violet-500/40 bg-violet-500/10 text-violet-300",
  MODEL: "border-accent/40 bg-accent/10 text-accent",
  UNAVAILABLE: "border-white/15 bg-white/[0.06] text-ink-faint",
};

const labels: Record<string, string> = {
  REAL: "REAL DATA",
  USER_REPORTED: "USER-REPORTED",
  SIMULATED: "DEMO / SIMULATED",
  CURATED: "CURATED STATIC",
  MODEL: "MODEL OUTPUT",
  UNAVAILABLE: "UNAVAILABLE",
};

export function ProvenanceBadge({
  provenance,
  className,
  ...props
}: { provenance: string } & HTMLAttributes<HTMLSpanElement>) {
  const key = provenance?.toUpperCase().replace(/[ -]/g, "_");
  return (
    <span
      className={cn(
        "inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide",
        styles[key] || styles.UNAVAILABLE,
        className,
      )}
      {...props}
    >
      {labels[key] || provenance}
    </span>
  );
}

// Live-OAuth provenance marker (§11–§13). Deliberately separate from
// ProvenanceBadge: these five values are what the account-connection UI must
// show verbatim, and FIXTURE must never be blurred into REAL.
const sourceStyles: Record<string, string> = {
  REAL: "border-emerald-500/40 bg-emerald-500/10 text-emerald-300",
  USER_PROVIDED: "border-sky-500/40 bg-sky-500/10 text-sky-300",
  SIMULATED: "border-amber-500/40 bg-amber-500/10 text-amber-300",
  FIXTURE: "border-violet-500/40 bg-violet-500/10 text-violet-300",
  UNAVAILABLE: "border-white/15 bg-white/[0.06] text-ink-faint",
};

const sourceLabels: Record<string, string> = {
  REAL: "REAL (LIVE API)",
  USER_PROVIDED: "YOU CONFIRMED",
  SIMULATED: "SIMULATED",
  FIXTURE: "FIXTURE — NOT REAL",
  UNAVAILABLE: "UNAVAILABLE",
};

export function SourceModeBadge({
  mode,
  className,
  ...props
}: { mode: string } & HTMLAttributes<HTMLSpanElement>) {
  const key = mode?.toUpperCase();
  return (
    <span
      className={cn(
        "inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide",
        sourceStyles[key] || sourceStyles.UNAVAILABLE,
        className,
      )}
      {...props}
    >
      {sourceLabels[key] || mode}
    </span>
  );
}

export function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    FINDING: "border-accent/40 bg-accent/10 text-accent",
    CHECKED_SAFE: "border-emerald-500/40 bg-emerald-500/10 text-emerald-300",
    NOT_CHECKED: "border-white/15 bg-white/[0.06] text-ink-muted",
    UNAVAILABLE: "border-amber-500/40 bg-amber-500/10 text-amber-300",
    // Live-OAuth: provider API does not expose this. Never rendered as safe.
    UNAVAILABLE_THROUGH_PROVIDER: "border-white/15 bg-white/[0.06] text-ink-faint",
  };
  return (
    <span
      className={cn(
        "inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide",
        map[status] || map.NOT_CHECKED,
      )}
    >
      {status.replace(/_/g, " ")}
    </span>
  );
}