import { useEffect, useState } from "react";
import { Mail, Users as UsersIcon } from "lucide-react";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import type { AccessCandidatesResult, AccessRecordRow, MemberInfo, Invitation, OrgAsset } from "@/lib/types";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input, Label, Select } from "@/components/ui/input";
import { cn } from "@/lib/utils";

export default function MembersPage() {
  const { role } = useAuth();
  const isAdmin = role === "ORG_ADMIN";
  const [members, setMembers] = useState<MemberInfo[]>([]);
  const [invitations, setInvitations] = useState<Invitation[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Invite form
  const [invEmail, setInvEmail] = useState("");
  const [invRole, setInvRole] = useState("MEMBER");
  const [invLink, setInvLink] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = async () => {
    try {
      const [m, i] = await Promise.all([
        api.listMembers(),
        isAdmin ? api.listInvitations() : Promise.resolve([]),
      ]);
      setMembers(m);
      setInvitations(i);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load members");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const invite = async () => {
    if (!invEmail) return;
    setBusy(true);
    setError(null);
    try {
      const res = await api.createInvitation(invEmail, invRole);
      setInvLink(res.invite_link);
      setInvEmail("");
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to send invitation");
    } finally {
      setBusy(false);
    }
  };

  if (loading) return <div className="text-sm text-ink-faint">Loading members…</div>;

  return (
    <div className="space-y-6 animate-fade-in">
      <header>
        <h1 className="text-2xl font-semibold text-ink">Members & Roles</h1>
        <p className="mt-1 text-sm text-ink-muted">
          Organization members and their RBAC roles. Admins can invite new members.
        </p>
      </header>

      {error && (
        <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-300">{error}</div>
      )}

      <Card>
        <CardHeader>
          <CardTitle><UsersIcon size={15} className="inline mr-1" /> Members ({members.length})</CardTitle>
        </CardHeader>
        <CardBody className="space-y-2">
          {members.map((m) => (
            <div key={m.membership_id} className="flex items-center justify-between glass-sub rounded-lg px-3 py-2">
              <div>
                <div className="text-sm text-ink">{m.email}</div>
                <div className="text-[11px] text-ink-faint">
                  Joined {new Date(m.joined_at).toLocaleDateString()} · {m.assets_owned} assets
                </div>
              </div>
              <span className={cn(
                "rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase",
                m.role === "ORG_ADMIN" ? "border-accent/40 text-accent" :
                m.role === "MEMBER" ? "border-emerald-500/40 text-emerald-300" :
                "border-white/15 text-ink-faint"
              )}>
                {m.role}
              </span>
            </div>
          ))}
        </CardBody>
      </Card>

      {/* Invitations (admin only) */}
      {isAdmin && (
        <>
          <Card>
            <CardHeader><CardTitle>Invite Member</CardTitle></CardHeader>
            <CardBody className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <Label>Email</Label>
                  <Input type="email" value={invEmail} onChange={(e) => setInvEmail(e.target.value)} placeholder="new@company.com" />
                </div>
                <div>
                  <Label>Role</Label>
                  <Select value={invRole} onChange={(e) => setInvRole(e.target.value)}>
                    <option value="MEMBER">MEMBER</option>
                    <option value="VIEWER">VIEWER</option>
                    <option value="ORG_ADMIN">ORG_ADMIN</option>
                  </Select>
                </div>
              </div>
              <Button variant="primary" size="sm" onClick={invite} disabled={busy || !invEmail}>
                <Mail size={14} /> Send invitation
              </Button>
              {invLink && (
                <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/5 px-4 py-3 text-sm text-emerald-200">
                  <div className="text-xs text-ink-faint mb-1">Invitation link (share privately):</div>
                  <code className="text-xs break-all">{invLink}</code>
                </div>
              )}
            </CardBody>
          </Card>

          {invitations.length > 0 && (
            <Card>
              <CardHeader><CardTitle>Pending Invitations</CardTitle></CardHeader>
              <CardBody className="space-y-2">
                {invitations.filter((i) => !i.used_at).map((i) => (
                  <div key={i.id} className="flex items-center justify-between glass-sub rounded-lg px-3 py-2 text-xs">
                    <div>
                      <span className="text-ink">{i.email}</span>
                      <span className="ml-2 text-ink-faint">{i.role}</span>
                    </div>
                    <span className="text-ink-faint">
                      expires {new Date(i.expires_at).toLocaleDateString()}
                    </span>
                  </div>
                ))}
              </CardBody>
            </Card>
          )}
        </>
      )}

      {/* §9.F access audit — admins declare + review; members see own rows */}
      <AccessAuditPanel isAdmin={isAdmin} members={members} />
    </div>
  );
}

function levelColor(level: string): string {
  if (level === "ADMIN") return "border-rose-500/40 text-rose-300";
  if (level === "USE") return "border-amber-500/40 text-amber-300";
  return "border-emerald-500/40 text-emerald-300";
}

function AccessAuditPanel({
  isAdmin,
  members,
}: {
  isAdmin: boolean;
  members: MemberInfo[];
}) {
  const [records, setRecords] = useState<AccessRecordRow[]>([]);
  const [assets, setAssets] = useState<OrgAsset[]>([]);
  const [memberId, setMemberId] = useState("");
  const [assetId, setAssetId] = useState("");
  const [level, setLevel] = useState("VIEW");
  const [candidates, setCandidates] = useState<AccessCandidatesResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const load = async () => {
    try {
      const [r, a] = await Promise.all([
        api.listAccessRecords(),
        isAdmin ? api.listAssets() : Promise.resolve([] as OrgAsset[]),
      ]);
      setRecords(r.records);
      setAssets(a);
      setError("");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load access records");
    }
  };

  useEffect(() => { load(); }, []);

  const declare = async () => {
    if (!memberId || !assetId) return;
    setBusy(true);
    setError("");
    try {
      await api.createAccessRecord(memberId, assetId, level);
      setMemberId("");
      setAssetId("");
      setLevel("VIEW");
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to declare access");
    } finally {
      setBusy(false);
    }
  };

  const act = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setError("");
    try {
      await fn();
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Action failed");
    } finally {
      setBusy(false);
    }
  };

  const scan = async () => {
    setBusy(true);
    setError("");
    try {
      setCandidates(await api.accessCandidates());
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Scan failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          Access Audit
          <span className="ml-2 text-[11px] font-normal text-ink-faint">
            declared member→asset access · review candidates
          </span>
        </CardTitle>
        {isAdmin && (
          <Button variant="primary" size="sm" onClick={scan} disabled={busy}>
            Run review scan
          </Button>
        )}
      </CardHeader>
      <CardBody className="space-y-3">
        <p className="text-[11px] text-ink-faint">
          These rows are administrator-declared access bookkeeping (never observed
          grants). Review candidates surface declared access that deserves
          re-confirmation: departed members, ADMIN-level access, and rows not
          re-confirmed within the review interval.
        </p>

        {error && (
          <div className="rounded-lg border border-rose-500/30 bg-rose-500/5 px-4 py-2 text-xs text-rose-200">
            {error}
          </div>
        )}

        {isAdmin && (
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-[1fr_1fr_auto_auto]">
            <Select value={memberId} onChange={(e) => setMemberId(e.target.value)}>
              <option value="">— member —</option>
              {members.filter((m) => m.is_active).map((m) => (
                <option key={m.membership_id} value={m.membership_id}>{m.email}</option>
              ))}
            </Select>
            <Select value={assetId} onChange={(e) => setAssetId(e.target.value)}>
              <option value="">— company asset —</option>
              {assets.map((a) => (
                <option key={a.id} value={a.asset_id}>{a.asset_id} ({a.asset_type})</option>
              ))}
            </Select>
            <Select value={level} onChange={(e) => setLevel(e.target.value)}>
              <option value="VIEW">VIEW</option>
              <option value="USE">USE</option>
              <option value="ADMIN">ADMIN</option>
            </Select>
            <Button onClick={declare} disabled={busy || !memberId || !assetId}>
              Declare access
            </Button>
          </div>
        )}

        {records.length === 0 ? (
          <p className="text-xs text-ink-faint">
            No access declarations {isAdmin ? "yet" : "about you"}.
          </p>
        ) : (
          <ul className="space-y-2">
            {records.map((r) => (
              <li key={r.id} className="glass-sub rounded-lg px-3 py-2">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-xs text-ink">
                      {isAdmin ? r.member_email : r.asset_id ?? "?"}
                      <span className={cn("ml-2 rounded border px-1.5 py-0.5 text-[10px] font-semibold", levelColor(r.level))}>
                        {r.level}
                      </span>
                      {r.status !== "ACTIVE" && (
                        <span className="ml-2 text-[10px] font-semibold text-rose-300">{r.status}</span>
                      )}
                    </div>
                    <div className="text-[11px] text-ink-faint">
                      {isAdmin ? r.asset_id : undefined}
                      {r.last_reviewed_at
                        ? ` · reviewed ${new Date(r.last_reviewed_at).toLocaleDateString()}`
                        : " · never re-confirmed"}
                    </div>
                  </div>
                  {isAdmin && r.status === "ACTIVE" && (
                    <div className="flex gap-2">
                      <Button size="sm" onClick={() => act(() => api.reviewAccessRecord(r.id))} disabled={busy}>
                        Mark reviewed
                      </Button>
                      <Button size="sm" variant="danger" onClick={() => act(() => api.removeAccessRecord(r.id))} disabled={busy}>
                        Remove
                      </Button>
                    </div>
                  )}
                </div>
              </li>
            ))}
          </ul>
        )}

        {candidates && (
          <div className="rounded-lg border border-white/10 bg-white/[0.04] p-3">
            <p className="text-xs font-semibold text-ink">
              Review candidates · interval {candidates.review_interval_days} days
              {candidates.assets.length === 0 && (
                <span className="ml-2 font-normal text-emerald-300">— nothing needs review</span>
              )}
            </p>
            <ul className="mt-2 space-y-2">
              {candidates.assets.map((a) => (
                <li key={a.asset_id} className="text-xs">
                  <span className="text-ink">{a.asset_id}</span>
                  <span className="ml-2 text-ink-faint">
                    {a.candidate_count} candidate{a.candidate_count === 1 ? "" : "s"} · severity{" "}
                    {a.severity.toFixed(2)}
                  </span>
                  <ul className="mt-1 space-y-0.5">
                    {a.candidates.map((c) => (
                      <li key={c.record_id} className="text-[11px] text-ink-muted">
                        {c.membership_ref} · {c.level} ·{" "}
                        {c.reasons.map((r) => r.code).join(", ")}
                      </li>
                    ))}
                  </ul>
                </li>
              ))}
            </ul>
            <p className="mt-2 text-[11px] text-ink-faint">{candidates.note}</p>
          </div>
        )}
      </CardBody>
    </Card>
  );
}

