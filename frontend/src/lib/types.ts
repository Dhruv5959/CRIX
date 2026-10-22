// Shared API types mirroring the backend Pydantic schemas.

export type DataProvenance =
  | "REAL"
  | "USER_REPORTED"
  | "SIMULATED"
  | "CURATED"
  | "MODEL"
  | "UNAVAILABLE";

// Provenance for account connections / compromise scenarios (live OAuth scope).
export type SourceMode = "REAL" | "USER_PROVIDED" | "SIMULATED" | "FIXTURE" | "UNAVAILABLE";

export type EventStatus =
  | "FINDING"
  | "CHECKED_SAFE"
  | "NOT_CHECKED"
  | "UNAVAILABLE"
  | "UNAVAILABLE_THROUGH_PROVIDER";
export type ExposureType = "PASSWORD_ONLY" | "PASSWORD_AND_SESSION" | "SESSION_ONLY";

export interface User {
  id: string;
  email: string;
  is_active: boolean;
  email_verified: boolean;
  totp_enabled: boolean;
  created_at: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_at: string;
  csrf_token: string;
}

export interface Account {
  id: string;
  account_id: string;
  label: string;
  service_name: string | null;
  platform: string | null;
  email: string | null;
  source: string;
  created_at: string;
}

export interface SecurityEvent {
  event_id: string;
  user_id: string;
  account_id: string;
  event_type: string;
  exposure_type: ExposureType | null;
  severity: number;
  confidence: number;
  source: string;
  source_mode: SourceMode;
  detected_at: string;
  status: EventStatus;
  metadata: Record<string, unknown>;
  provenance: string;
}

export interface Correlation {
  rule_id: string;
  title: string;
  correlation_type: string;
  severity: number;
  confidence: number;
  explanation: string;
  contributing_event_ids: string[];
}

export interface RiskResult {
  score: number;
  band: string;
  confidence: string;
  range_low: number;
  range_high: number;
  base_risk: number;
  interaction_risk: number;
  mitigation_credit: number;
  components: { features: Record<string, number> };
}

export interface Attribution {
  method: string;
  total_risk: number;
  contributions: Record<string, number>;
  sum_of_contributions: number;
  efficiency_error: number;
  compute_ms: number;
}

export interface Plan {
  method: string;
  actions: string[];
  total_effort: number;
  risk_after: number;
  risk_reduction: number;
  compute_ms: number;
}

export interface PlannerComparison {
  initial_risk: number;
  greedy: Plan;
  exact: Plan;
  optimality_gap: number;
  is_greedy_trap: boolean;
}

export interface AnalysisResult {
  run_id: string;
  generated_at: string;
  events: SecurityEvent[];
  correlations: Correlation[];
  risk: RiskResult;
  attribution: Attribution;
  planner: PlannerComparison;
  features: Record<string, number>;
}

export interface Explanation {
  summary: string;
  citations: Array<{
    edge_id: string;
    predicate: string;
    from: string;
    to: string;
    evidence: string;
    source: string;
  }>;
  context: Record<string, unknown>;
  grounded: boolean;
  unsupported_claims: string[];
  statements: Array<{ text: string; citations: string[] }>;
}

export interface GraphPayload {
  nodes: Array<{ id: string; label: string; curated: boolean; connected?: boolean }>;
  edges: Array<{
    source: string;
    target: string;
    weight: number;
    relationship_type: string;
    description: string;
    source_ref: string;
    last_verified_at: string | null;
    curated: boolean;
  }>;
  ranking: Array<{
    service: string;
    pagerank: number;
    weighted_in_degree: number;
    dependents: string[];
    rank: number;
  }>;
  provenance: string;
}

export interface PhishingResult {
  label: string;
  confidence: number;
  ai_generated_label: string | null;
  ai_generated_confidence: number | null;
  model_version: string;
  signals: Array<{ type: string; detail: string[]; weight: string }>;
  provenance: string;
  note: string;
}

export interface WhatIfResult {
  applied_actions: string[];
  before: { score: number; band: string; attribution: Attribution };
  after: {
    score: number;
    band: string;
    confidence: string;
    range_low: number;
    range_high: number;
    base_risk: number;
    interaction_risk: number;
    mitigation_credit: number;
    attribution: Attribution;
    features: Record<string, number>;
  };
  delta: number;
}

export interface EvaluationSummary {
  measured: boolean;
  note: string;
  suites: Record<
    string,
    { metrics: Record<string, number>; details: Record<string, unknown>; measured: boolean }
  >;
}

export interface Health {
  status: string;
  version: string;
  env: string;
  hibp_configured: boolean;
  /** Resolved provider for the next email-breach lookup ("xposedornot" | "hibp"). */
  breach_email_provider: string;
  breach_email_provider_label: string;
}

// --------------------------------------------------------------------------- //
// Live account connections + compromise propagation (live OAuth scope)
// --------------------------------------------------------------------------- //
export interface OAuthProviderInfo {
  key: string;
  label: string;
  configured: boolean;
  status: "AVAILABLE" | "NOT_CONFIGURED";
  account_requirement: string;
  scopes: string[];
  exposes: string[];
  does_not_expose: string[];
  docs_url: string;
}

export interface ProviderCapability {
  provider: string;
  capability: string;
  available: boolean;
  source: string;
  last_verified: string | null;
  note: string;
  status: "AVAILABLE" | "UNAVAILABLE_THROUGH_PROVIDER";
}

export interface ProviderConnection {
  id: string;
  provider: string;
  provider_label: string;
  provider_account_id: string;
  identifier: string | null;
  display_name: string | null;
  connection_status: string;
  source_mode: SourceMode;
  scopes: string;
  connected_at: string | null;
  last_synced_at: string | null;
  account_id: string | null;
  token_available: boolean;
}

export interface RelationshipType {
  key: string;
  label: string;
}

export interface AccountRelationship {
  id: string;
  from_account_id: string;
  to_account_id: string;
  from_label: string | null;
  to_label: string | null;
  relationship_type: string;
  relationship_label: string;
  source: string;
  source_mode: SourceMode;
  confidence: number;
  weight: number;
  created_at: string;
}

export interface PropagationAccount {
  account_id: string;
  label: string;
  provider: string | null;
  source_mode: SourceMode;
  downstream_count: number;
}

export interface DownstreamAccount {
  account_id: string;
  label: string;
  provider: string | null;
  source_mode: SourceMode;
  exposure: number;
  band: string;
  path: string[];
  path_length: number;
  reasons: string[];
  components: {
    dependency_strength: number;
    account_criticality: number;
    credential_auth_weakness: number;
    /** true when the account has no recorded events — scored as unknown, not safe. */
    weakness_unknown?: boolean;
    path_exposure: number;
    mitigation_credit: number;
  };
}

export interface PropagationAnalysis {
  upstream_account_id: string;
  upstream_label: string;
  source_mode: SourceMode;
  affected_count: number;
  overall_band: string;
  highest_risk_account_id: string | null;
  highest_risk_account_label: string | null;
  downstream: DownstreamAccount[];
  formula: string;
  params: Record<string, unknown>;
  disclaimer: string;
}

export interface SimulationResult {
  run_id: string;
  scenario: {
    label: string;
    upstream_account_id: string;
    upstream_label: string;
    source_mode: SourceMode;
    notice: string;
  };
  propagation: PropagationAnalysis;
  scenario_risk: {
    score: number;
    band: string;
    range_low: number;
    range_high: number;
    base_risk: number;
    interaction_risk: number;
    mitigation_credit: number;
  };
  scenario_attribution: Attribution;
  scenario_plan: {
    budget: number;
    comparison: PlannerComparison;
    base_comparison: PlannerComparison;
    note: string;
  };
  storyline: Array<{
    account_id: string;
    label: string;
    band: string;
    is_upstream: boolean;
    path?: string[];
    path_length?: number;
    source_mode: SourceMode;
  }>;
  disclaimer: string;
}