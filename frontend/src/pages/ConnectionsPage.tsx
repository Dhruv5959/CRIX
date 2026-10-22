import { useCallback, useEffect, useState } from "react";
import {
  AlertTriangle,
  Link2,
  Plug,
  RefreshCw,
  ShieldCheck,
  Trash2,
  Unlink,
} from "lucide-react";
import { api, ApiError } from "@/lib/api";
import type {
  AccountRelationship,
  Account,
  OAuthProviderInfo,
  ProviderCapability,
  ProviderConnection,
  RelationshipType,
} from "@/lib/types";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Label, Select } from "@/components/ui/input";
import { SourceModeBadge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

// Live account connections (official OAuth) + the user-confirmed relationship
// layer. Provenance is shown verbatim on every row (§11–§13).
export default function ConnectionsPage() {
  const [providers, setProviders] = useState<Record<string, OAuthProviderInfo> | null>(null);
  const [connections, setConnections] = useState<ProviderConnection[]>([]);
  const [capabilities, setCapabilities] = useState<ProviderCapability[]>([]);
  const [capNote, setCapNote] = useState("");
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [relationships, setRelationships] = useState<AccountRelationship[]>([]);
  const [relTypes, setRelTypes] = useState<RelationshipType[]>([]);
  const [relNote, setRelNote] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(async () => {
    const [prov, conns, caps, accs, rels, types] = await Promise.all([
      api.oauthProviders(),
      api.oauthConnections(),
      api.oauthCapabilities(),
      api.listAccounts(),
      api.listRelationships(),
      api.relationshipTypes(),
    ]);
    setProviders(prov.providers);
    setConnections(conns.connections);
    setCapabilities(caps.capabilities);
    setCapNote(caps.note);
    setAccounts(accs);
    setRelationships(rels);
    setRelTypes(types.types);
    setRelNote(types.note);
  }, []);

  useEffect(() => {
    load().catch(() => setError("Could not load connections."));
  }, [load]);

  // The OAuth callback lands on /connections?oauth_success=… | ?oauth_error=…
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const ok = params.get("oauth_success");
    const err = params.get("oauth_error");
    if (ok) {
      setMessage(`${ok} connected.`);
      window.history.replaceState({}, "", window.location.pathname);
      load().catch(() => undefined);
    } else if (err) {
      setError(`Connection failed (${err}).`);
      window.history.replaceState({}, "", window.location.pathname);
    }
  }, [load]);

  async function connect(provider: string) {
    setBusy(provider);
    setError(null);
    try {
      const res = await api.oauthAuthorize(provider);
      window.location.href = res.authorize_url;
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not start the connection.");
      setBusy(null);
    }
  }

  async function connectFixture(provider: string) {
    setBusy(provider);
    setError(null);
    try {
      const res = await api.oauthFixture(provider);
      setMessage(res.notice);
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Fixture unavailable.");
    } finally {
      setBusy(null);
    }
  }

  async function disconnect(id: string) {
    setBusy(id);
    try {
      await api.oauthDisconnect(id);
      await load();
    } finally {
      setBusy(null);
    }
  }

  const unavailableCaps = capabilities.filter((c) => !c.available);

  return (
    <div className="space-y-6 animate-fade-in">
      <header>
        <h1 className="text-2xl font-semibold text-ink">Live Account Connections</h1>
        <p className="mt-1 max-w-3xl text-sm text-ink-muted">
          Connect accounts through official OAuth. CRIX never asks for your Google, LinkedIn, or
          Instagram password, never stores provider credentials, and never sends OAuth tokens to the
          browser. A connection proves an <em>authorized relationship</em> — it does not by itself
          reveal that provider's security posture.
        </p>
      </header>

      {message && (
        <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/5 px-4 py-3 text-sm text-emerald-200">
          {message}
        </div>
      )}
      {error && (
        <div className="flex items-start gap-2 rounded-lg border border-rose-500/30 bg-rose-500/5 px-4 py-3 text-sm text-rose-200">
          <AlertTriangle size={15} className="mt-0.5 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* ---------------------------------------------------------------- */}
      {/* Providers                                                        */}
      {/* ---------------------------------------------------------------- */}
      <Card>
        <CardHeader>
          <CardTitle>Providers</CardTitle>
          <span className="text-[11px] text-ink-faint">authorization-code + PKCE (S256)</span>
        </CardHeader>
        <CardBody className="grid grid-cols-1 gap-4 lg:grid-cols-3">
          {providers === null && (
            <p className="text-sm text-ink-faint">Loading providers…</p>
          )}
          {providers &&
            Object.values(providers).map((p) => {
              const existing = connections.find((c) => c.provider === p.key);
              return (
                <div
                  key={p.key}
                  className="flex flex-col glass-sub rounded-lg p-4"
                >
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <div className="text-sm font-semibold text-ink">{p.label}</div>
                      <div className="mt-0.5 text-[11px] text-ink-faint">{p.account_requirement}</div>
                    </div>
                    {existing ? (
                      <SourceModeBadge mode={existing.source_mode} />
                    ) : (
                      <span
                        className={cn(
                          "inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide",
                          p.configured
                            ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
                            : "border-white/15 bg-white/[0.06] text-ink-faint",
                        )}
                      >
                        {p.status}
                      </span>
                    )}
                  </div>

                  {existing ? (
                    <div className="mt-3 space-y-1 text-[11px] text-ink-muted">
                      <div className="truncate text-ink">{existing.display_name || existing.identifier}</div>
                      {existing.identifier && <div className="truncate">{existing.identifier}</div>}
                      <div>
                        status {existing.connection_status} ·{" "}
                        {existing.token_available ? "token stored (encrypted)" : "no token"}
                      </div>
                      <div className="text-ink-faint">
                        last synced {existing.last_synced_at ? new Date(existing.last_synced_at).toLocaleString() : "—"}
                      </div>
                    </div>
                  ) : (
                    <div className="mt-3 text-[11px] text-ink-faint">
                      {p.configured
                        ? "Not connected yet."
                        : "NOT_CONFIGURED — register an app and set the client id/secret."}
                    </div>
                  )}

                  <div className="mt-3 flex flex-wrap gap-2">
                    {existing ? (
                      <Button
                        size="sm"
                        variant="danger"
                        disabled={busy === existing.id}
                        onClick={() => disconnect(existing.id)}
                      >
                        <Unlink size={13} /> Disconnect
                      </Button>
                    ) : (
                      <>
                        <Button
                          size="sm"
                          variant="primary"
                          disabled={!p.configured || busy === p.key}
                          onClick={() => connect(p.key)}
                        >
                          <Plug size={13} /> Connect
                        </Button>
                        <Button size="sm" disabled={busy === p.key} onClick={() => connectFixture(p.key)}>
                          Demo fixture
                        </Button>
                      </>
                    )}
                  </div>

                  <details className="mt-3">
                    <summary className="cursor-pointer text-[11px] text-ink-faint">
                      What this API exposes / does not expose
                    </summary>
                    <ul className="mt-2 space-y-1 text-[11px]">
                      {p.exposes.map((item) => (
                        <li key={item} className="text-emerald-300">
                          ✓ {item}
                        </li>
                      ))}
                      {p.does_not_expose.map((item) => (
                        <li key={item} className="text-ink-faint">
                          ✗ {item}{" "}
                          <span className="text-amber-300">(UNAVAILABLE_THROUGH_PROVIDER)</span>
                        </li>
                      ))}
                    </ul>
                  </details>
                </div>
              );
            })}
        </CardBody>
      </Card>

      {/* ---------------------------------------------------------------- */}
      {/* Connections                                                      */}
      {/* ---------------------------------------------------------------- */}
      <Card>
        <CardHeader>
          <CardTitle>Connected accounts</CardTitle>
          <span className="text-[11px] text-ink-faint">
            OAuth tokens are encrypted at rest and never returned to this page
          </span>
        </CardHeader>
        <CardBody className="space-y-2">
          {connections.length === 0 && (
            <p className="text-sm text-ink-faint">
              No live connections yet. Each connection becomes an asset in the dependency graph
              (e.g. <code className="font-mono">google_…</code>).
            </p>
          )}
          {connections.map((c) => (
            <div
              key={c.id}
              className="flex flex-wrap items-center gap-3 glass-sub rounded-lg px-3 py-2"
            >
              <span className="text-sm text-ink">{c.provider_label}</span>
              <span className="text-[11px] text-ink-muted">{c.display_name || c.identifier}</span>
              <span className="font-mono text-[11px] text-ink-faint">{c.account_id}</span>
              <div className="ml-auto flex items-center gap-2">
                <SourceModeBadge mode={c.source_mode} />
                <button
                  className="text-ink-faint hover:text-rose-300"
                  aria-label="disconnect"
                  onClick={() => disconnect(c.id)}
                >
                  <Trash2 size={14} />
                </button>
              </div>
            </div>
          ))}
        </CardBody>
      </Card>

      {/* ---------------------------------------------------------------- */}
      {/* Capability matrix                                                */}
      {/* ---------------------------------------------------------------- */}
      <Card>
        <CardHeader>
          <CardTitle>Provider capability matrix</CardTitle>
          <span className="text-[11px] text-ink-faint">
            a connection never flips a capability to available
          </span>
        </CardHeader>
        <CardBody className="space-y-3">
          <p className="text-[11px] leading-relaxed text-ink-faint">{capNote}</p>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-white/10 text-[10px] uppercase tracking-wide text-ink-faint">
                  <th className="py-2 pr-3">Provider</th>
                  <th className="py-2 pr-3">Capability</th>
                  <th className="py-2 pr-3">Available?</th>
                  <th className="py-2 pr-3">Source</th>
                  <th className="py-2">Last verified</th>
                </tr>
              </thead>
              <tbody>
                {capabilities.map((c) => (
                  <tr key={`${c.provider}:${c.capability}`} className="border-b border-white/[0.07]">
                    <td className="py-2 pr-3 text-ink-muted">{c.provider}</td>
                    <td className="py-2 pr-3 text-ink">{c.capability}</td>
                    <td className="py-2 pr-3">
                      <span
                        className={cn(
                          "rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase",
                          c.available
                            ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
                            : "border-white/15 bg-white/[0.06] text-ink-faint",
                        )}
                      >
                        {c.available ? "YES" : "UNAVAILABLE_THROUGH_PROVIDER"}
                      </span>
                    </td>
                    <td className="py-2 pr-3 text-[11px] text-ink-faint">{c.source}</td>
                    <td className="py-2 text-[11px] text-ink-faint">
                      {c.last_verified ? new Date(c.last_verified).toLocaleDateString() : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {unavailableCaps.length > 0 && (
            <p className="flex items-start gap-2 text-[11px] text-amber-200">
              <AlertTriangle size={13} className="mt-0.5 shrink-0" />
              {unavailableCaps.length} capability(ies) are not exposed by the official API. CRIX
              marks them UNAVAILABLE_THROUGH_PROVIDER — never SAFE.
            </p>
          )}
        </CardBody>
      </Card>

      {/* ---------------------------------------------------------------- */}
      {/* User-confirmed relationships                                     */}
      {/* ---------------------------------------------------------------- */}
      <RelationshipEditor
        accounts={accounts}
        relationships={relationships}
        relTypes={relTypes}
        note={relNote}
        onChanged={load}
      />
    </div>
  );
}

function RelationshipEditor({
  accounts,
  relationships,
  relTypes,
  note,
  onChanged,
}: {
  accounts: Account[];
  relationships: AccountRelationship[];
  relTypes: RelationshipType[];
  note: string;
  onChanged: () => Promise<void>;
}) {
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [type, setType] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!type && relTypes.length) setType(relTypes[0].key);
  }, [relTypes, type]);

  async function add() {
    if (!from || !to || !type) return;
    setBusy(true);
    setError(null);
    try {
      await api.createRelationship({
        from_account_id: from,
        to_account_id: to,
        relationship_type: type,
        confidence: 1.0,
      });
      setTo("");
      await onChanged();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not save the relationship.");
    } finally {
      setBusy(false);
    }
  }

  async function remove(id: string) {
    setBusy(true);
    try {
      await api.deleteRelationship(id);
      await onChanged();
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>How are these accounts related?</CardTitle>
        <SourceModeBadge mode="USER_PROVIDED" />
      </CardHeader>
      <CardBody className="space-y-4">
        <p className="text-[11px] leading-relaxed text-ink-faint">{note}</p>

        <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 px-3 py-2 text-[11px] text-amber-200">
          CRIX never infers a recovery path from an OAuth login. Every edge below was confirmed by
          you and is stored with <code className="font-mono">source = USER_CONFIRMED</code>.
        </div>

        {relationships.length > 0 && (
          <div className="space-y-2">
            {relationships.map((r) => (
              <div
                key={r.id}
                className="flex flex-wrap items-center gap-2 glass-sub rounded-lg px-3 py-2 text-xs"
              >
                <Link2 size={13} className="text-ink-faint" />
                <span className="text-ink">{r.from_label || r.from_account_id}</span>
                <span className="glass-chip rounded border px-1.5 py-0.5 text-[10px] uppercase text-accent">
                  {r.relationship_label}
                </span>
                <span className="text-ink">→</span>
                <span className="text-ink">{r.to_label || r.to_account_id}</span>
                <span className="ml-auto font-mono text-[10px] text-ink-faint">
                  w={r.weight.toFixed(2)}
                </span>
                <SourceModeBadge mode={r.source_mode} />
                <button
                  className="text-ink-faint hover:text-rose-300"
                  aria-label="delete relationship"
                  onClick={() => remove(r.id)}
                >
                  <Trash2 size={13} />
                </button>
              </div>
            ))}
          </div>
        )}

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <div>
            <Label>From account</Label>
            <Select value={from} onChange={(e) => setFrom(e.target.value)}>
              <option value="">Select…</option>
              {accounts.map((a) => (
                <option key={a.account_id} value={a.account_id}>
                  {a.label}
                </option>
              ))}
            </Select>
          </div>
          <div>
            <Label>Relationship</Label>
            <Select value={type} onChange={(e) => setType(e.target.value)}>
              {relTypes.map((t) => (
                <option key={t.key} value={t.key}>
                  {t.label}
                </option>
              ))}
            </Select>
          </div>
          <div>
            <Label>To account</Label>
            <Select value={to} onChange={(e) => setTo(e.target.value)}>
              <option value="">Select…</option>
              {accounts
                .filter((a) => a.account_id !== from)
                .map((a) => (
                  <option key={a.account_id} value={a.account_id}>
                    {a.label}
                  </option>
                ))}
            </Select>
          </div>
        </div>

        {error && <p className="text-xs text-rose-300">{error}</p>}

        <div className="flex items-center gap-3">
          <Button variant="primary" size="sm" onClick={add} disabled={busy || !from || !to || !type}>
            <Link2 size={14} /> Confirm relationship
          </Button>
          <span className="flex items-center gap-1 text-[11px] text-ink-faint">
            <RefreshCw size={11} /> weights feed the propagation model
          </span>
          <span className="flex items-center gap-1 text-[11px] text-ink-faint">
            <ShieldCheck size={11} /> stored as YOU CONFIRMED
          </span>
        </div>
      </CardBody>
    </Card>
  );
}
