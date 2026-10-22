// Phase 6 frontend test (§5.12, test 26): organization asset graph mapping.
//
// Asserts the pure view-model only — the mapping never invents assets, never
// labels a reachable asset as compromised, and keeps declared direction
// separate from exposure semantics. No DOM library is added; nothing here
// contacts a network. All fixtures are SYNTHETIC.

import { describe, expect, it } from "vitest";
import {
  CRITICAL_CRITICALITY,
  formatPath,
  pathUncertainty,
  stepNote,
  toOrgGraphView,
} from "./orgGraph";
import type { OrgGraphPayload, OrgGraphPath, OrgGraphStep } from "./types";

function makeStep(overrides: Partial<OrgGraphStep> = {}): OrgGraphStep {
  return {
    from_asset_id: "alice@acme.example",
    to_asset_id: "github.com/acme/api",
    traversed_from: "alice@acme.example",
    traversed_to: "github.com/acme/api",
    relationship_id: "rel-1",
    relationship_type: "RESETS_PASSWORD",
    directed: true,
    exposure: "forward",
    traversal_condition:
      "Administrator-declared relationship; exposure is modeled along the documented direction of this relationship type.",
    evidence: {
      edge_source: "ADMIN_DECLARED",
      note: "SYNTHETIC note",
      note_present: true,
      declared_at: "2026-10-01T00:00:00+00:00",
    },
    uncertainty: [],
    provenance: "ADMIN_DECLARED",
    criticality_of_target: 5,
    ...overrides,
  };
}

function makePayload(): OrgGraphPayload {
  return {
    nodes: [
      {
        asset_id: "alice@acme.example",
        asset_type: "WORK_EMAIL",
        label: "Alice mailbox",
        criticality: 4,
        source_mode: "USER_PROVIDED",
        provenance: "REGISTERED_ASSET",
      },
      {
        asset_id: "github.com/acme/api",
        asset_type: "CODE_REPOSITORY",
        label: "API repo",
        criticality: 5,
        source_mode: "USER_PROVIDED",
        provenance: "REGISTERED_ASSET",
      },
      {
        asset_id: "acme-backup",
        asset_type: "CLOUD_STORAGE",
        label: "Backups",
        criticality: 2,
        source_mode: "USER_PROVIDED",
        provenance: "REGISTERED_ASSET",
      },
    ],
    edges: [
      {
        relationship_id: "rel-1",
        from_asset_id: "alice@acme.example",
        to_asset_id: "github.com/acme/api",
        relationship_type: "RESETS_PASSWORD",
        directed: true,
        exposure: "forward",
        edge_source: "ADMIN_DECLARED",
        weight: 1.0,
        note: "SYNTHETIC note",
        declared_at: "2026-10-01T00:00:00+00:00",
        provenance: "ADMIN_DECLARED",
      },
      {
        relationship_id: "rel-2",
        from_asset_id: "github.com/acme/api",
        to_asset_id: "acme-backup",
        relationship_type: "DEPENDS_ON",
        directed: true,
        exposure: "reverse",
        edge_source: "ADMIN_DECLARED",
        weight: 1.0,
        note: "",
        declared_at: "2026-10-01T00:00:00+00:00",
        provenance: "ADMIN_DECLARED",
      },
    ],
    stats: {
      assets: 3,
      relationships: 2,
      skipped_unsupported_type: 0,
      skipped_dangling_endpoint: 0,
      duplicate_edges_skipped: 0,
    },
    limits: { default_depth: 3, max_depth: 5 },
    provenance_labels: { REGISTERED_ASSET: "Registered company asset." },
    supported_relationship_types: ["DEPENDS_ON", "RESETS_PASSWORD"],
    disclaimer:
      "Potential exposure only. It is not evidence that any attack or compromise has occurred.",
  };
}

describe("toOrgGraphView", () => {
  it("maps every registered asset and declared relationship exactly once", () => {
    const view = toOrgGraphView(makePayload());
    // The server returns nodes already sorted; the helper preserves that order.
    expect(view.nodes.map((n) => n.id)).toEqual([
      "alice@acme.example",
      "github.com/acme/api",
      "acme-backup",
    ]);
    expect(view.links.map((l) => l.id)).toEqual(["rel-1", "rel-2"]);
  });

  it("keeps edge orientation in declared direction and exposure as data", () => {
    const view = toOrgGraphView(makePayload());
    const dependsOn = view.links.find((l) => l.id === "rel-2")!;
    // The picture shows what was declared (repo depends on backup); the
    // reverse exposure semantics survive as a field, not a flipped arrow.
    expect(dependsOn.source).toBe("github.com/acme/api");
    expect(dependsOn.target).toBe("acme-backup");
    expect(dependsOn.exposure).toBe("reverse");
  });

  it("flags critical assets by criticality without relabeling anything", () => {
    const view = toOrgGraphView(makePayload());
    const byId = new Map(view.nodes.map((n) => [n.id, n]));
    expect(byId.get("github.com/acme/api")!.critical).toBe(true);
    expect(byId.get("alice@acme.example")!.critical).toBe(true);
    expect(byId.get("acme-backup")!.critical).toBe(false);
    expect(CRITICAL_CRITICALITY).toBe(4);
    // No node is described as breached, hacked or compromised.
    expect(JSON.stringify(view)).not.toMatch(/breached|hacked|compromised/i);
  });

  it("marks a link critical when its target asset is critical", () => {
    const view = toOrgGraphView(makePayload());
    expect(view.links.find((l) => l.id === "rel-1")!.critical).toBe(true);
    expect(view.links.find((l) => l.id === "rel-2")!.critical).toBe(false);
  });

  it("produces an empty view for an empty graph", () => {
    const empty = { ...makePayload(), nodes: [], edges: [] };
    expect(toOrgGraphView(empty)).toEqual({ nodes: [], links: [] });
  });
});

describe("formatPath", () => {
  it("renders each hop as declared, annotated with its relationship type", () => {
    const path: OrgGraphPath = {
      assets: ["alice@acme.example", "github.com/acme/api"],
      length: 1,
      steps: [makeStep()],
      provenance: "DERIVED_PATH",
    };
    expect(formatPath(path)).toBe(
      "alice@acme.example --RESETS_PASSWORD--> github.com/acme/api",
    );
  });
});

describe("pathUncertainty", () => {
  it("collects and sorts deduplicated uncertainty flags across steps", () => {
    const path: OrgGraphPath = {
      assets: ["a", "b", "c"],
      length: 2,
      steps: [
        makeStep({ uncertainty: ["NOTE_MISSING"] }),
        makeStep({ uncertainty: [] }),
        makeStep({ uncertainty: ["NOTE_MISSING", "STALE_SOURCE"] }),
      ],
      provenance: "DERIVED_PATH",
    };
    expect(pathUncertainty(path)).toEqual(["NOTE_MISSING", "STALE_SOURCE"]);
  });

  it("returns no flags for a fully evidenced path", () => {
    const path: OrgGraphPath = {
      assets: ["a", "b"],
      length: 1,
      steps: [makeStep({ uncertainty: [] })],
      provenance: "DERIVED_PATH",
    };
    expect(pathUncertainty(path)).toEqual([]);
  });
});

describe("stepNote", () => {
  it("returns the recorded note when one exists", () => {
    expect(stepNote(makeStep())).toBe("SYNTHETIC note");
  });

  it("states plainly when no note was recorded — never implying evidence exists", () => {
    const step = makeStep({
      evidence: { edge_source: "ADMIN_DECLARED", note: "", note_present: false, declared_at: null },
      uncertainty: ["NOTE_MISSING"],
    });
    expect(stepNote(step)).toBe("No note recorded for this relationship.");
    expect(step.uncertainty).toContain("NOTE_MISSING");
  });
});
