// Thin API client. Access token is kept in memory (never localStorage) to reduce
// XSS token theft; the refresh token lives in an httpOnly cookie. State-changing
// auth calls echo the CSRF token returned by the server.

import type {
  Account,
  AccountRelationship,
  AccessCandidatesResult,
  AccessRecordRow,
  AdminView,
  AnalysisResult,
  AssetDependency,
  BreachMonitorStatus,
  DomainChecksResult,
  EmailVerifyConfirmResult,
  EmailVerifyRequestResult,
  DomainListEntry,
  DomainOwnership,
  DomainRegistrationResult,
  RepoScanResult,
  EvaluationSummary,
  Explanation,
  GraphPayload,
  Health,
  Invitation,
  InvitationCreated,
  MemberDetail,
  MemberInfo,
  OAuthProviderInfo,
  OrgAsset,
  OrgGraphBlastRadius,
  OrgGraphNeighbors,
  OrgGraphPayload,
  OrgGraphPaths,
  OrgInfo,
  PhishingResult,
  PropagationAccount,
  ProviderCapability,
  ProviderConnection,
  RelationshipType,
  RemediationPlanResult,
  RemediationSettings,
  RemediationTask,
  RemediationTaskDetail,
  RiskHistoryEntry,
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
  if (!headers.has("Content-Type") && options.body && !(options.body instanceof FormData)) {
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
  register: (email: string, password: string, breachMonitorConsent = false) =>
    request<User>("/api/auth/register", {
      method: "POST",
      auth: false,
      // Feature A: affirmative opt-in, stored server-side with a timestamp.
      body: JSON.stringify({ email, password, breach_monitor_consent: breachMonitorConsent }),
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
    request<{ events: SecurityEvent[]; cached: boolean }>("/api/signals/breach", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  // Feature A: consent-gated automatic monitoring of the REGISTERED work email.
  // Lookup runs at sign-in only when the last check is older than 24h; this
  // status/consent pair carries state, never a verdict on a password.
  monitorStatus: () => request<BreachMonitorStatus>("/api/signals/breach/monitor/status"),
  setBreachMonitorConsent: (enabled: boolean) =>
    request<BreachMonitorStatus>("/api/signals/breach/monitor/consent", {
      method: "POST",
      body: JSON.stringify({ enabled }),
    }),
  passwordHygiene: (payload: Record<string, unknown>) =>
    request<{ provider: unknown; events: SecurityEvent[] }>("/api/signals/password-hygiene", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  providers: () =>
    request<{ providers: Array<Record<string, unknown>>; provenance: string }>("/api/providers"),
  analyzePhishing: (text: string, url = "") =>
    request<PhishingResult>("/api/signals/phishing/analyze", {
      method: "POST",
      body: JSON.stringify({ text, url }),
    }),
  phishingStatus: () =>
    request<{ artifacts_available: boolean; note: string }>("/api/signals/phishing/status"),
  recordPhishing: (accountId: string, text: string, url = "") =>
    request<{ result: PhishingResult; events: SecurityEvent[] }>(
      `/api/signals/phishing/${accountId}/record`,
      { method: "POST", body: JSON.stringify({ text, url }) },
    ),
  // --- §7.D domain posture (admin-only) -------------------------------------
  registerDomain: (domain: string, label: string) =>
    request<DomainRegistrationResult>("/api/domains/register", {
      method: "POST",
      body: JSON.stringify({ domain, label }),
    }),
  listDomains: () =>
    request<{ domains: DomainListEntry[]; count: number }>("/api/domains"),
  verifyDomainOwnership: (assetId: string, token: string) =>
    request<{ verified: boolean; reason: string; ownership?: DomainOwnership }>(
      `/api/domains/${encodeURIComponent(assetId)}/ownership/verify`,
      { method: "POST", body: JSON.stringify({ token }) },
    ),
  refreshDomainOwnership: (assetId: string) =>
    request<DomainRegistrationResult>(
      `/api/domains/${encodeURIComponent(assetId)}/ownership/refresh`,
      { method: "POST" },
    ),
  runDomainChecks: (assetId: string, dkimSelector: string | null) =>
    request<DomainChecksResult>(`/api/domains/${encodeURIComponent(assetId)}/checks`, {
      method: "POST",
      body: JSON.stringify({ dkim_selector: dkimSelector }),
    }),
  // --- §8.E repository secret scan (multipart upload; no form body JSON) -----
  scanRepository: (assetId: string, file: File) => {
    const form = new FormData();
    form.append("asset_id", assetId);
    form.append("file", file, file.name || "repo.zip");
    return request<RepoScanResult>("/api/repo-scan", { method: "POST", body: form });
  },
  // --- §9.F access review (admin declares; members see own rows) --------------
  listAccessRecords: () =>
    request<{ count: number; scope: string; records: AccessRecordRow[] }>("/api/access/records"),
  createAccessRecord: (membershipId: string, assetId: string, level: string) =>
    request<AccessRecordRow>("/api/access/records", {
      method: "POST",
      body: JSON.stringify({ membership_id: membershipId, asset_id: assetId, level }),
    }),
  // --- registered-email verification (consent gate; token via email only) -----
  requestEmailVerification: () =>
    request<EmailVerifyRequestResult>("/api/auth/email/verify/request", { method: "POST" }),
  confirmEmailVerification: (token: string) =>
    request<EmailVerifyConfirmResult>("/api/auth/email/verify/confirm", {
      method: "POST",
      body: JSON.stringify({ token }),
    }),
  removeAccessRecord: (recordId: string) =>
    request<{ id: string; status: string; removed_at: string }>(
      `/api/access/records/${encodeURIComponent(recordId)}`,
      { method: "DELETE" },
    ),
  reviewAccessRecord: (recordId: string) =>
    request<{ id: string; status: string; last_reviewed_at: string }>(
      `/api/access/records/${encodeURIComponent(recordId)}/review`,
      { method: "POST" },
    ),
  accessCandidates: () => request<AccessCandidatesResult>("/api/access/candidates"),
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

  // --- organization ---
  getOrg: () => request<OrgInfo>("/api/org"),
  updateOrg: (name: string) =>
    request<OrgInfo>("/api/org", { method: "PATCH", body: JSON.stringify({ name }) }),
  listMembers: () => request<MemberInfo[]>("/api/members"),
  getMember: (membershipId: string) =>
    request<MemberDetail>(`/api/members/${membershipId}`),
  adminViews: () => request<AdminView[]>("/api/org/admin-views"),
  createInvitation: (email: string, role: string = "MEMBER") =>
    request<InvitationCreated>("/api/invitations", {
      method: "POST",
      body: JSON.stringify({ email, role }),
    }),
  listInvitations: () => request<Invitation[]>("/api/invitations"),
  acceptInvitation: (token: string, password?: string) =>
    request<{ detail: string; email: string; role: string; org_id: string }>(
      "/api/invitations/accept",
      {
        method: "POST",
        body: JSON.stringify({ token, password: password || undefined }),
        // No `auth: false` here: when the invited email already has an
        // account, the backend requires a session for THAT account, so a
        // held access token must be attached automatically.
      },
    ),

  // --- org assets ---
  listAssets: () => request<OrgAsset[]>("/api/assets"),
  createAsset: (payload: {
    asset_id: string;
    asset_type: string;
    label: string;
    criticality?: number;
    service_name?: string;
  }) => request<OrgAsset>("/api/assets", { method: "POST", body: JSON.stringify(payload) }),
  getAsset: (assetId: string) => request<OrgAsset>(`/api/assets/${assetId}`),
  updateAsset: (assetId: string, payload: Record<string, unknown>) =>
    request<OrgAsset>(`/api/assets/${assetId}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    }),
  deleteAsset: (assetId: string) =>
    request<void>(`/api/assets/${assetId}`, { method: "DELETE" }),
  listDependencies: () => request<AssetDependency[]>("/api/dependencies"),
  createDependency: (payload: {
    from_asset_id: string;
    to_asset_id: string;
    relationship_type: string;
    weight?: number;
    note?: string;
  }) =>
    request<AssetDependency>("/api/dependencies", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  // --- remediation tasks ---
  remediationSettings: () => request<RemediationSettings>("/api/remediation/settings"),
  updateRemediationSettings: (effort_budget: number) =>
    request<RemediationSettings>("/api/remediation/settings", {
      method: "PATCH",
      body: JSON.stringify({ effort_budget }),
    }),
  listTasks: () => request<RemediationTask[]>("/api/remediation/tasks"),
  createTask: (payload: {
    action_key: string;
    target_asset_id?: string;
    finding_ids?: string[];
    effort?: number;
    verification_method?: string;
  }) =>
    request<RemediationTask>("/api/remediation/tasks", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  getTask: (taskId: string) =>
    request<RemediationTaskDetail>(`/api/remediation/tasks/${taskId}`),
  updateTask: (taskId: string, payload: Record<string, unknown>) =>
    request<RemediationTask>(`/api/remediation/tasks/${taskId}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    }),
  completeTask: (taskId: string) =>
    request<RemediationTask>(`/api/remediation/tasks/${taskId}/complete`, { method: "POST" }),
  verifyTask: (taskId: string, payload: { method: string; attested?: boolean; evidence_refs?: string[] }) =>
    request<RemediationTask>(`/api/remediation/tasks/${taskId}/verify`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  reopenTask: (taskId: string, reason?: string) =>
    request<RemediationTask>(`/api/remediation/tasks/${taskId}/reopen`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    }),
  remediationPlan: (budget?: number) =>
    // The backend reads `budget` as a (bound) query parameter — a JSON body
    // with budget was silently ignored.
    request<RemediationPlanResult>(
      budget !== undefined
        ? `/api/remediation/plan?budget=${encodeURIComponent(String(budget))}`
        : "/api/remediation/plan",
      { method: "POST" },
    ),

  // --- risk history ---
  riskHistory: () =>
    request<{ entries: RiskHistoryEntry[] }>("/api/risk-history"),
};
