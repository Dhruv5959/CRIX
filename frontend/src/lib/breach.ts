// Pure presentation logic for one email-breach lookup.
//
// This module only turns the normalized events the backend returns into what the
// UI shows. It never decides anything: status, provider and timestamp come
// straight from the server, so a provider failure (UNAVAILABLE) can never be
// rendered here as a clean result. Keeping it pure and free of React means the
// "what the user sees" rules are unit-tested directly (breach.test.ts).

import type { EventStatus, SecurityEvent } from "./types";

export const PROVIDER_LABELS: Record<string, string> = {
  xposedornot: "XposedOrNot (free community API)",
  hibp: "Have I Been Pwned",
};

export type BreachLevel = "HIGH" | "MEDIUM" | "LOW" | "CLEAR" | "UNKNOWN" | "NONE";

export interface BreachLookupSummary {
  status: EventStatus;
  provider: string | null;
  providerLabel: string;
  checkedAt: string | null;
  /** "Checked" when a verdict was reached, "Attempted" when the lookup failed. */
  timeLabel: string;
  timeText: string;
  breaches: string[];
  breachCount: number;
  truncated: boolean;
  reason: string;
  /** Honesty note for placeholder-style addresses ("no real email"): the
   * verdict on such an address is not meaningful evidence about a mailbox. */
  addressWarning: string | null;
  severity: number;
  confidence: number;
  level: BreachLevel;
  headline: string;
  detail: string;
  /** True only when a live provider actually answered. */
  hasVerdict: boolean;
}

const HEADLINES: Record<string, string> = {
  FINDING: "Breach exposure reported",
  CHECKED_SAFE: "No indexed breach reported",
  UNAVAILABLE: "Provider could not be consulted",
  UNAVAILABLE_THROUGH_PROVIDER: "Not available through this provider",
  NOT_CHECKED: "Not checked yet",
};

/** Deterministic UTC rendering so the UI and tests never depend on locale/TZ. */
export function formatCheckedAt(iso: string | null): string {
  if (!iso) return "not recorded";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "not recorded";
  const pad = (n: number) => String(n).padStart(2, "0");
  return (
    `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())} ` +
    `${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())} UTC`
  );
}

/**
 * Build the view model for the breach lookup.
 *
 * The simulated session-exposure scenario is deliberately excluded: it is a
 * constructed scenario, not a live provider answer, and mixing the two would
 * blur provenance.
 */
export function summarizeBreachLookup(events: SecurityEvent[]): BreachLookupSummary {
  const lookup = (events ?? []).filter(
    (e) => e.event_type === "BREACH_EXPOSURE" || e.event_type === "IDENTITY_EXPOSED",
  );

  if (lookup.length === 0) {
    return {
      status: "NOT_CHECKED",
      provider: null,
      providerLabel: "—",
      checkedAt: null,
      timeLabel: "Checked",
      timeText: "not checked yet",
      breaches: [],
      breachCount: 0,
      truncated: false,
      reason: "",
      addressWarning: null,
      severity: 0,
      confidence: 0,
      level: "NONE",
      headline: HEADLINES.NOT_CHECKED,
      detail: "Run a lookup to see whether this address appears in known breach data.",
      hasVerdict: false,
    };
  }

  const primary = lookup.find((e) => e.event_type === "BREACH_EXPOSURE") ?? lookup[0];
  const meta = (primary.metadata ?? {}) as Record<string, unknown>;

  const asString = (key: string): string | null =>
    typeof meta[key] === "string" ? (meta[key] as string) : null;
  const asNumber = (key: string, fallback: number): number =>
    typeof meta[key] === "number" ? (meta[key] as number) : fallback;

  const breaches = Array.isArray(meta.breaches)
    ? (meta.breaches as unknown[]).filter((n): n is string => typeof n === "string" && n.length > 0)
    : [];
  const status = primary.status;
  const hasVerdict = status === "FINDING" || status === "CHECKED_SAFE";
  const severity = typeof primary.severity === "number" ? primary.severity : 0;
  const provider = asString("provider") ?? primary.source ?? null;

  return {
    status,
    provider,
    providerLabel:
      asString("provider_label") ?? (provider ? PROVIDER_LABELS[provider] ?? provider : "—"),
    checkedAt: asString("checked_at"),
    timeLabel: hasVerdict ? "Checked" : "Attempted",
    timeText: formatCheckedAt(asString("checked_at")),
    breaches,
    breachCount: asNumber("breach_count", breaches.length),
    truncated: meta.breaches_truncated === true,
    reason: asString("reason") ?? "",
    addressWarning: asString("address_warning"),
    severity,
    confidence: typeof primary.confidence === "number" ? primary.confidence : 0,
    level: levelFor(status, severity),
    headline: HEADLINES[status] ?? HEADLINES.NOT_CHECKED,
    detail: detailFor(status, asNumber("breach_count", breaches.length), severity),
    hasVerdict,
  };
}

/** Severity is reserved colour territory: rose finding / amber unknown / emerald clear. */
export function levelFor(status: string, severity: number): BreachLevel {
  switch (status) {
    case "CHECKED_SAFE":
      return "CLEAR";
    case "FINDING":
      if (severity >= 0.7) return "HIGH";
      if (severity >= 0.45) return "MEDIUM";
      return "LOW";
    case "NOT_CHECKED":
      return "NONE";
    default:
      // UNAVAILABLE / UNAVAILABLE_THROUGH_PROVIDER: unknown, never clear.
      return "UNKNOWN";
  }
}

function detailFor(status: string, breachCount: number, severity: number): string {
  if (status === "FINDING") {
    const noun = breachCount === 1 ? "breach" : "breaches";
    return (
      `The provider reports this address in ${breachCount} indexed ${noun}. ` +
      `Signal strength ${severity.toFixed(2)} of 1.00 is a relative weight, not a ` +
      "probability — CRIX's risk engine decides the score."
    );
  }
  if (status === "CHECKED_SAFE") {
    return (
      "The provider returned no indexed breach for this address. Absence of a record " +
      "is not proof that the account is uncompromised."
    );
  }
  if (status === "UNAVAILABLE" || status === "UNAVAILABLE_THROUGH_PROVIDER") {
    return (
      "No verdict was reached, so this is UNKNOWN — not a clean result and never " +
      "treated as safe."
    );
  }
  return "Run a lookup to see whether this address appears in known breach data.";
}