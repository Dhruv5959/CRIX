// Thin API client. Access token is kept in memory (never localStorage) to reduce
// XSS token theft; the refresh token lives in an httpOnly cookie. State-changing
// auth calls echo the CSRF token returned by the server.

import type {
  Account,
  AccountRelationship,
  AnalysisResult,
  EvaluationSummary,
  Explanation,
  GraphPayload,
  Health,
  OAuthProviderInfo,
  OrgGraphBlastRadius,
  OrgGraphNeighbors,
  OrgGraphPayload,
  OrgGraphPaths,
  PhishingResult,
  PropagationAccount,
  ProviderCapability,
  ProviderConnection,
  RelationshipType,
  SecurityEvent,
  SimulationResult,
  TokenResponse,
  User,
  WhatIfResult,
} from "./types";

let accessToken: string | null = null;
let csrfToken: string | null = null;

export function setTokens(access: string | null, csrf: string | null) {
  accessToken = access;
  csrfToken = csrf;
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(
  path: string,
  options: RequestInit & { auth?: boolean; csrf?: boolean } = {},
): Promise<T> {
  const headers = new Headers(options.headers || {});
  if (!headers.has("Content-Type") && options.body) {
    headers.set("Content-Type", "application/json");
  }
  if (options.auth !== false && accessToken) {
    headers.set("Authorization", `Bearer ${accessToken}`);
  }
  if (options.csrf && csrfToken) {
    headers.set("X-CSRF-Token", csrfToken);
  }
  const response = await fetch(path, {
    ...options,
    headers,
    credentials: "include",
  });
  if (response.status === 204) return undefined as T;
  const text = await response.text();
  const data = text ? JSON.parse(text) : null;
  if (!response.ok) {
    const detail = data?.detail;
    throw new ApiError(response.status, typeof detail === "string" ? detail : "Request failed");
  }
  return data as T;
}

export const api = {
  // --- auth ---
  register: (email: string, password: string) =>
    request<User>("/api/auth/register", {
      method: "POST",
      auth: false,
      body: JSON.stringify({ email, password }),
    }),
  login: async (email: string, password: string, totp?: string) => {
    const data = await request<TokenResponse>("/api/auth/login", {
      method: "POST",
      auth: false,
      body: JSON.stringify({ email, password, totp_code: totp || null }),
    });
    setTokens(data.access_token, data.csrf_token);
    return data;
  },
  refresh: async () => {
    const data = await request<TokenResponse>("/api/auth/refresh", {
      method: "POST",
      auth: false,
      csrf: true,
    });
    setTokens(data.access_token, data.csrf_token);
    return data;
  },
  logout: async () => {
    try {
      await request<void>("/api/auth/logout", { method: "POST", csrf: true });
    } finally {
      setTokens(null, null);
    }
  },
  me: () => request<User>("/api/auth/me"),
  // Password reset: request emails a single-use token (dev writes it to
  // backend/artifacts/outbox/), confirm consumes it. The link the email
  // contains points at /reset-password?token=… — handled by ResetPasswordPage.
  passwordResetRequest: (email: string) =>
    request<{ detail: string }>("/api/auth/password-reset/request", {
      method: "POST",
      auth: false,
      body: JSON.stringify({ email }),
    }),
  passwordResetConfirm: (token: string, newPassword: string) =>
    request<{ detail: string }>("/api/auth/password-reset/confirm", {
      method: "POST",
      auth: false,
      body: JSON.stringify({ token, new_password: newPassword }),
    }),

  // --- accounts ---
  listAccounts: () => request<Account[]>("/api/accounts"),
  createAccount: (payload: Partial<Account> & { account_id: string; label: string }) =>
    request<Account>("/api/accounts", { method: "POST", body: JSON.stringify(payload) }),
  deleteAccount: (accountId: string) =>
    request<void>(`/api/accounts/${accountId}`, { method: "DELETE" }),

  // --- signals ---
  breachCheck: (payload: {
    account_id: string;
    email: string;
    simulated_exposure_type?: string | null;
    simulated_mfa_bypass_capable?: boolean;
  }) =>
    request<{ events: SecurityEvent[] }>("/api/signals/breach", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  passwordHygiene: (payload: Record<string, unknown>) =>
    request<{ provider: unknown; events: SecurityEvent[] }>("/api/signals/password-hygiene", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  providers: () =>
    request<{ providers: Array<Record<string, unknown>>; provenance: string }>("/api/providers"),
  analyzePhishing: (text: string) =>
    request<PhishingResult>("/api/signals/phishing/analyze", {
      method: "POST",
      body: JSON.stringify({ text }),
    }),
  phishingStatus: () =>
    request<{ artifacts_available: boolean; note: string }>("/api/signals/phishing/status"),
  recordPhishing: (accountId: string, text: string) =>
    request<{ result: PhishingResult; events: SecurityEvent[] }>(
      `/api/signals/phishing/${accountId}/record`,
      { method: "POST", body: JSON.stringify({ text }) },
    ),
  permissionAudit: (payload: Record<string, unknown>) =>
    request<{ classification_report: unknown[]; events: SecurityEvent[] }>(
      "/api/signals/permissions/audit",
      { method: "POST", body: JSON.stringify(payload) },
    ),

  // --- analysis ---
  runAnalysis: () => request<AnalysisResult>("/api/analysis/run", { method: "POST" }),
  summary: () => request<AnalysisResult>("/api/analysis/summary"),
  events: () => request<{ events: SecurityEvent[] }>("/api/analysis/events"),
  explanation: () => request<Explanation>("/api/analysis/explanation"),
  whatIf: (toggles: Array<{ action_key: string; enabled: boolean }>) =>
    request<WhatIfResult>("/api/analysis/what-if", {
      method: "POST",
      body: JSON.stringify({ toggles }),
    }),

  // --- graph / planner / knowledge ---
  graph: () => request<GraphPayload>("/api/graph"),
  // Organization asset dependency graph (Phase 6, §5): potential exposure
  // along declared relationships — never a claim of compromise.
  orgGraph: () => request<OrgGraphPayload>("/api/org/graph"),
  orgGraphNeighbors: (assetId: string, direction: "in" | "out" | "both" = "both") =>
    request<OrgGraphNeighbors>(
      `/api/org/graph/neighbors?asset_id=${encodeURIComponent(assetId)}&direction=${direction}`,
    ),
  orgGraphPaths: (source: string, target: string, maxDepth?: number) => {
    const params = new URLSearchParams({ source, target });
    if (maxDepth !== undefined) params.set("max_depth", String(maxDepth));
    return request<OrgGraphPaths>(`/api/org/graph/paths?${params.toString()}`);
  },
  orgGraphBlastRadius: (assetId: string, maxDepth?: number) => {
    const params = new URLSearchParams({ asset_id: assetId });
    if (maxDepth !== undefined) params.set("max_depth", String(maxDepth));
    return request<OrgGraphBlastRadius>(`/api/org/graph/blast-radius?${params.toString()}`);
  },
  plannerPlan: (budget = 6) =>
    request<{ budget: number; comparison: unknown; note: string }>(
      `/api/planner/plan?budget=${budget}`,
    ),
  plannerActions: () =>
    request<{ actions: Array<Record<string, unknown>>; note: string }>("/api/planner/actions"),
  correlationRules: () => request<{ rules: unknown[]; engine: string }>("/api/correlation-rules"),
  knowledgeGraph: () => request<{ nodes: unknown[]; edges: unknown[]; provenance: string }>(
    "/api/knowledge-graph",
  ),
  evaluation: () => request<EvaluationSummary>("/api/evaluation"),
  health: () => request<Health>("/api/health", { auth: false }),

  // --- live account connections (OAuth) ---
  oauthProviders: () => request<{ providers: Record<string, OAuthProviderInfo> }>("/api/oauth/providers"),
  oauthCapabilities: () =>
    request<{ capabilities: ProviderCapability[]; note: string }>("/api/oauth/capabilities"),
  oauthAuthorize: (provider: string) =>
    request<{ authorize_url: string; provider: string; state: string }>(
      `/api/oauth/${provider}/authorize`,
    ),
  oauthConnections: () => request<{ connections: ProviderConnection[] }>("/api/oauth/connections"),
  oauthFixture: (provider: string) =>
    request<{ provider: string; source_mode: string; account_id: string; notice: string }>(
      `/api/oauth/fixtures/${provider}`,
      { method: "POST" },
    ),
  oauthDisconnect: (connectionId: string) =>
    request<void>(`/api/oauth/connections/${connectionId}`, { method: "DELETE" }),

  // --- user-confirmed relationships ---
  relationshipTypes: () =>
    request<{ types: RelationshipType[]; note: string; weights: Record<string, number> }>(
      "/api/relationships/types",
    ),
  listRelationships: () => request<AccountRelationship[]>("/api/relationships"),
  createRelationship: (payload: {
    from_account_id: string;
    to_account_id: string;
    relationship_type: string;
    confidence?: number;
  }) =>
    request<AccountRelationship>("/api/relationships", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  deleteRelationship: (id: string) =>
    request<void>(`/api/relationships/${id}`, { method: "DELETE" }),

  // --- compromise propagation ---
  propagationAccounts: () =>
    request<{ accounts: PropagationAccount[] }>("/api/propagation/accounts"),
  simulateCompromise: (upstreamAccountId: string) =>
    request<SimulationResult>("/api/propagation/simulate", {
      method: "POST",
      body: JSON.stringify({ upstream_account_id: upstreamAccountId }),
    }),

  passwordRange: (prefix: string) =>
    request<{ prefix: string; suffixes: string; k_anonymity: boolean }>(
      `/api/password-check/range/${prefix}`,
      { auth: false },
    ),
};