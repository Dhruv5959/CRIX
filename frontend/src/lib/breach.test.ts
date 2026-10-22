// Rendering + view-model tests for the email-breach result (integration spec §9).
//
// The app has no DOM test library and none is being added for this, so the pure
// view-model is asserted directly and the component is rendered to markup with
// react-dom/server (already a dependency). Nothing here contacts a network.

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { BreachResult } from "../components/BreachResult";
import { formatCheckedAt, levelFor, summarizeBreachLookup } from "./breach";
import type { EventStatus, SecurityEvent } from "./types";

const CHECKED_AT = "2026-10-20T13:31:23.248193+00:00";
const TIME_TEXT = "2026-10-20 13:31:23 UTC";
const LABEL = "XposedOrNot (free community API)";

function makeEvent(overrides: Partial<SecurityEvent> = {}): SecurityEvent {
  return {
    event_id: "evt-1",
    user_id: "user-1",
    account_id: "acct-1",
    event_type: "BREACH_EXPOSURE",
    exposure_type: null,
    severity: 0,
    confidence: 0,
    source: "xposedornot",
    source_mode: "REAL",
    detected_at: CHECKED_AT,
    status: "CHECKED_SAFE",
    metadata: {
      provider: "xposedornot",
      provider_label: LABEL,
      checked_at: CHECKED_AT,
      breach_count: 0,
      breaches: [],
    },
    provenance: "test",
    ...overrides,
  };
}

function eventsWithStatus(status: EventStatus, extra: Record<string, unknown> = {}): SecurityEvent[] {
  return [makeEvent({
    status,
    severity: 0,
    confidence: status === "FINDING" ? 0.9 : 0,
    metadata: {
      provider: "xposedornot",
      provider_label: LABEL,
      checked_at: CHECKED_AT,
      breach_count: 0,
      breaches: [],
      ...extra,
    },
  })];
}

function findingEvents(): SecurityEvent[] {
  return [
    makeEvent({
      event_id: "evt-breach",
      status: "FINDING",
      severity: 0.55,
      confidence: 0.9,
      metadata: {
        provider: "xposedornot",
        provider_label: LABEL,
        checked_at: CHECKED_AT,
        breach_count: 3,
        breaches: ["Adobe", "Chegg", "LinkedIn"],
        breaches_truncated: false,
        exposed_data_classes: "UNAVAILABLE_THROUGH_PROVIDER",
      },
    }),
    makeEvent({
      event_id: "evt-identity",
      event_type: "IDENTITY_EXPOSED",
      status: "FINDING",
      severity: 0.4,
      metadata: { provider: "xposedornot", checked_at: CHECKED_AT },
    }),
  ];
}

function render(events: SecurityEvent[]): string {
  return renderToStaticMarkup(
    createElement(BreachResult, { summary: summarizeBreachLookup(events) }),
  );
}

describe("summarizeBreachLookup", () => {
  it("summarizes a live finding with provider, names and time", () => {
    const s = summarizeBreachLookup(findingEvents());

    expect(s.status).toBe("FINDING");
    expect(s.provider).toBe("xposedornot");
    expect(s.providerLabel).toBe(LABEL);
    expect(s.breaches).toEqual(["Adobe", "Chegg", "LinkedIn"]);
    expect(s.breachCount).toBe(3);
    expect(s.truncated).toBe(false);
    expect(s.checkedAt).toBe(CHECKED_AT);
    expect(s.timeLabel).toBe("Checked");
    expect(s.timeText).toBe(TIME_TEXT);
    expect(s.level).toBe("MEDIUM");
    expect(s.hasVerdict).toBe(true);
  });

  it("reports an unavailable lookup as UNKNOWN with the provider's reason", () => {
    const s = summarizeBreachLookup(
      eventsWithStatus("UNAVAILABLE", { reason: "XposedOrNot free-tier budget exhausted" }),
    );

    expect(s.status).toBe("UNAVAILABLE");
    expect(s.level).toBe("UNKNOWN");
    expect(s.hasVerdict).toBe(false);
    expect(s.timeLabel).toBe("Attempted");
    expect(s.reason).toContain("budget exhausted");
    expect(s.detail).toContain("UNKNOWN");
    expect(s.headline).toBe("Provider could not be consulted");
  });

  it("treats a provider negative as clear, while refusing to call it proof", () => {
    const s = summarizeBreachLookup(eventsWithStatus("CHECKED_SAFE"));

    expect(s.status).toBe("CHECKED_SAFE");
    expect(s.level).toBe("CLEAR");
    expect(s.hasVerdict).toBe(true);
    expect(s.breaches).toEqual([]);
    expect(s.breachCount).toBe(0);
    expect(s.detail).toContain("not proof");
  });

  it("returns NOT_CHECKED when no lookup events exist", () => {
    const s = summarizeBreachLookup([]);

    expect(s.status).toBe("NOT_CHECKED");
    expect(s.level).toBe("NONE");
    expect(s.hasVerdict).toBe(false);
    expect(s.providerLabel).toBe("—");
  });

  it("ignores the simulated session scenario (it is not a provider answer)", () => {
    const s = summarizeBreachLookup([
      makeEvent({
        event_type: "SESSION_EXPOSURE",
        source: "simulated",
        source_mode: "SIMULATED",
        status: "FINDING",
        severity: 0.9,
        exposure_type: "SESSION_ONLY",
      }),
    ]);

    expect(s.status).toBe("NOT_CHECKED");
    expect(s.hasVerdict).toBe(false);
  });

  it("keeps the full breach count when the name list is capped", () => {
    const names = Array.from({ length: 20 }, (_, i) => `Breach${i}`);
    const s = summarizeBreachLookup(
      eventsWithStatus("FINDING", { breach_count: 140, breaches: names, breaches_truncated: true }),
    );

    expect(s.breachCount).toBe(140);
    expect(s.breaches).toHaveLength(20);
    expect(s.truncated).toBe(true);
  });

  it("falls back to its own provider map, then to the raw provider key", () => {
    const known = summarizeBreachLookup(
      eventsWithStatus("CHECKED_SAFE", { provider_label: undefined }),
    );
    expect(known.providerLabel).toBe(LABEL);

    const unknown = summarizeBreachLookup(
      eventsWithStatus("CHECKED_SAFE", {
        provider: "some-other-api",
        provider_label: undefined,
      }),
    );
    expect(unknown.providerLabel).toBe("some-other-api");
  });
});

describe("levelFor", () => {
  it("maps severity bands for a finding", () => {
    expect(levelFor("FINDING", 0.85)).toBe("HIGH");
    expect(levelFor("FINDING", 0.55)).toBe("MEDIUM");
    expect(levelFor("FINDING", 0.3)).toBe("LOW");
  });

  it("never maps an unverifiable status to CLEAR", () => {
    expect(levelFor("UNAVAILABLE", 0)).toBe("UNKNOWN");
    expect(levelFor("UNAVAILABLE_THROUGH_PROVIDER", 0.9)).toBe("UNKNOWN");
    expect(levelFor("NOT_CHECKED", 0)).toBe("NONE");
    expect(levelFor("CHECKED_SAFE", 0.85)).toBe("CLEAR");
  });
});

describe("formatCheckedAt", () => {
  it("renders a stable UTC timestamp regardless of locale", () => {
    expect(formatCheckedAt(CHECKED_AT)).toBe(TIME_TEXT);
  });

  it("does not invent a time it does not have", () => {
    expect(formatCheckedAt(null)).toBe("not recorded");
    expect(formatCheckedAt("not-a-date")).toBe("not recorded");
  });
});

describe("BreachResult rendering", () => {
  it("renders breach names, provider and last-checked time", () => {
    const html = render(findingEvents());

    expect(html).toContain("Breach exposure reported");
    expect(html).toContain("Adobe");
    expect(html).toContain("LinkedIn");
    expect(html).toContain(LABEL);
    expect(html).toContain(TIME_TEXT);
    expect(html).toContain("MEDIUM");
    expect(html).toContain("REAL (LIVE API)");
    expect(html).toContain("not a probability");
    expect(html).not.toContain("+0 more"); // 3 of 3 names shown, so no overflow chip
  });

  it("marks a failed lookup UNKNOWN and never as a clean result", () => {
    const html = render(
      eventsWithStatus("UNAVAILABLE", { reason: "XposedOrNot free-tier budget exhausted" }),
    );

    expect(html).toContain("UNAVAILABLE");
    expect(html).toContain("Provider could not be consulted");
    expect(html).toContain("budget exhausted");
    expect(html).toContain("Attempted");
    expect(html).not.toContain("No indexed breach reported");
    expect(html).not.toContain("REAL (LIVE API)");
  });

  it("shows a provider negative as a checked result", () => {
    const html = render(eventsWithStatus("CHECKED_SAFE"));

    expect(html).toContain("No indexed breach reported");
    expect(html).toContain("Checked");
    expect(html).toContain(LABEL);
    expect(html).not.toContain("Breach exposure reported");
  });

  it("renders the +N more chip only when names were truncated", () => {
    const names = Array.from({ length: 20 }, (_, i) => `Breach${i}`);
    const html = render(
      eventsWithStatus("FINDING", { breach_count: 140, breaches: names, breaches_truncated: true }),
    );

    expect(html).toContain("+120 more");
  });
});
