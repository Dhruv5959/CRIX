import { useEffect, useState } from "react";
import { Mail, Plus, Users as UsersIcon } from "lucide-react";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import type { MemberInfo, Invitation } from "@/lib/types";
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
    </div>
  );
}

