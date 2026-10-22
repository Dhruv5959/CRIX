import { cn } from "@/lib/utils";

const bandStyles: Record<string, string> = {
  CRITICAL: "text-rose-300 border-rose-500/40",
  HIGH: "text-orange-300 border-orange-500/40",
  MODERATE: "text-amber-300 border-amber-500/40",
  LOW: "text-emerald-300 border-emerald-500/40",
};

export function bandColor(band: string): string {
  return bandStyles[band] || "text-ink-muted border-white/15";
}

/** A compact, honest score display. The accent arc encodes the score; the
 * numeric value and sensitivity range are always shown so we never imply false
 * precision. */
export function RiskGauge({
  score,
  band,
  rangeLow,
  rangeHigh,
  size = 168,
}: {
  score: number;
  band: string;
  rangeLow?: number;
  rangeHigh?: number;
  size?: number;
}) {
  const radius = size / 2 - 14;
  const circumference = 2 * Math.PI * radius;
  const value = Math.max(0, Math.min(100, score));
  const dash = (value / 100) * circumference;
  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative" style={{ width: size, height: size }}>
        <svg width={size} height={size} className="-rotate-90">
          <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="rgba(148,163,184,0.12)" strokeWidth={10} />
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke="#22d3ee"
            strokeWidth={10}
            strokeLinecap="round"
            strokeDasharray={`${dash} ${circumference}`}
            style={{
              filter: "drop-shadow(0 0 6px rgba(34,211,238,0.45))",
              transition: "stroke-dasharray 0.6s ease",
            }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="font-mono text-4xl font-semibold text-ink">{value.toFixed(0)}</span>
          <span
            className={cn(
              "mt-1 rounded border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide",
              bandColor(band),
            )}
          >
            {band}
          </span>
        </div>
      </div>
      {rangeLow !== undefined && rangeHigh !== undefined && (
        <p className="text-center text-[11px] text-ink-faint">
          sensitivity range {rangeLow.toFixed(0)}–{rangeHigh.toFixed(0)}
        </p>
      )}
    </div>
  );
}