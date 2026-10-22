// Pure mapping helpers for the organization asset dependency graph (Phase 6).
//
// These functions transform API payloads into render-ready shapes. They never
// derive risk, never assert compromise, and never merge assets by name — the
// server already resolved identity and scope; this layer only formats.

import type { OrgGraphPayload, OrgGraphPath, OrgGraphStep } from "./types";

/** Criticality at or above which an asset is highlighted as critical. */
export const CRITICAL_CRITICALITY = 4;

export interface OrgGraphLink {
  id: string;
  source: string;
  target: string;
  relationship_type: string;
  exposure: "forward" | "reverse" | "both";
  note: string;
  critical: boolean;
}

export interface OrgGraphView {
  nodes: Array<{ id: string; label: string; asset_type: string; criticality: number; critical: boolean }>;
  links: OrgGraphLink[];
}

/**
 * Map an `OrgGraphPayload` into nodes/links for the force graph.
 *
 * Edge orientation follows the DECLARED direction (from -> to) so the picture
 * matches what an administrator wrote down; exposure semantics live in the
 * `exposure` field, not in the picture's arrow direction.
 */
export function toOrgGraphView(payload: OrgGraphPayload): OrgGraphView {
  return {
    nodes: payload.nodes.map((n) => ({
      id: n.asset_id,
      label: n.label || n.asset_id,
      asset_type: n.asset_type,
      criticality: n.criticality,
      critical: n.criticality >= CRITICAL_CRITICALITY,
    })),
    links: payload.edges.map((e) => ({
      id: e.relationship_id,
      source: e.from_asset_id,
      target: e.to_asset_id,
      relationship_type: e.relationship_type,
      exposure: e.exposure,
      note: e.note,
      critical:
        (payload.nodes.find((n) => n.asset_id === e.to_asset_id)?.criticality ?? 0) >=
        CRITICAL_CRITICALITY,
    })),
  };
}

/**
 * Format one path as a readable "A -> B -> C" string with each hop annotated
 * by its declared relationship type. Honest wording: this is a documented
 * exposure path, not an attack trace.
 */
export function formatPath(path: OrgGraphPath): string {
  return path.steps
    .map((step) => `${step.from_asset_id} --${step.relationship_type}--> ${step.to_asset_id}`)
    .join("\n");
}

/** Collect the uncertainty flags present across a path's steps (deduplicated). */
export function pathUncertainty(path: OrgGraphPath): string[] {
  const flags = new Set<string>();
  for (const step of path.steps) {
    for (const flag of step.uncertainty) flags.add(flag);
  }
  return [...flags].sort();
}

/** The note a relationship step carries, or a placeholder when none exists. */
export function stepNote(step: OrgGraphStep): string {
  return step.evidence.note_present && step.evidence.note
    ? step.evidence.note
    : "No note recorded for this relationship.";
}
