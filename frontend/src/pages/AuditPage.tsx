import { useEffect, useState } from "react";
import { Eye, EyeOff, Shield } from "lucide-react";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import type { AdminView } from "@/lib/types";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";

const ROLE_PERMISSIONS = [
  { role: "ORG_ADMIN", section: "Assets", canSee: "Full CRUD (create, read, update, delete)", cannotSee: "—" },
  { role: "ORG_ADMIN", section: "Members", canSee: "All members, their roles, assets owned, detail views (audit-logged)", cannotSee: "Member passwords or authentication secrets" },
  { role: "ORG_ADMIN", section: "Tasks", canSee: "All tasks, can create/verify/reopen", cannotSee: "—" },
  { role: "ORG_ADMIN", section: "Risk & Attribution", canSee: "Full risk scores, Shapley attribution, model version", cannotSee: "—" },
  { role: "ORG_ADMIN", section: "Invitations", canSee: "Create/list invitations with role selection", cannotSee: "—" },
  { role: "MEMBER", section: "Assets", canSee: "Read all assets, own assets", cannotSee: "Cannot create/delete assets" },
  { role: "MEMBER", section: "Members", canSee: "Member list (emails, roles)", cannotSee: "Member detail views, admin-view audit log" },
  { role: "MEMBER", section: "Tasks", canSee: "All tasks, can complete assigned tasks", cannotSee: "Cannot create tasks, verify, or reopen" },
  { role: "VIEWER", section: "Assets", canSee: "Read all assets", cannotSee: "Cannot create/update/delete" },
  { role: "VIEWER", section: "Members", canSee: "Member list", cannotSee: "Member detail, admin views" },
  { role: "VIEWER", section: "Tasks", canSee: "Read tasks", cannotSee: "Cannot modify, complete, verify, or reopen" },
];

export default function AuditPage() {
  const { role } = useAuth();
  const [adminViews, setAdminViews] = useState<AdminView[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (role !== "ORG_ADMIN") {
      setLoading(false);
      return;
    }
    api.adminViews()
      .then(setAdminViews)
      .catch((e) => setError(e instanceof Error ? e.message : "Failed to load audit log"))
      .finally(() => setLoading(false));
  }, [role]);

  if (role !== "ORG_ADMIN") {
    return (
      <div className="space-y-6 animate-fade-in">
        <header>
          <h1 className="text-2xl font-semibold text-ink">Audit & RBAC</h1>
        </header>
        <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 px-4 py-3 text-sm text-amber-200">
          This page is restricted to ORG_ADMIN users.
        </div>
      </div>
    );
  }

  if (loading) return <div className="text-sm text-ink-faint">Loading audit data…</div>;

  return (
    <div className="space-y-6 animate-fade-in">
      <header>
        <h1 className="text-2xl font-semibold text-ink">Audit & RBAC</h1>
        <p className="mt-1 text-sm text-ink-muted">
          Who can see what, and a log of admin access to member data.
        </p>
      </header>

      {error && (
        <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-300">{error}</div>
      )}

      {/* Role permissions matrix */}
      <Card>
        <CardHeader>
          <CardTitle><Shield size={15} className="inline mr-1" /> Who Can See What</CardTitle>
        </CardHeader>
        <CardBody>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-white/10 text-[10px] uppercase tracking-wide text-ink-faint">
                  <th className="py-2 pr-3">Role</th>
                  <th className="py-2 pr-3">Section</th>
                  <th className="py-2 pr-3"><Eye size={11} className="inline" /> Can see</th>
                  <th className="py-2"><EyeOff size={11} className="inline" /> Cannot see</th>
                </tr>
              </thead>
              <tbody>
                {ROLE_PERMISSIONS.map((p, i) => (
                  <tr key={i} className="border-b border-white/[0.07]">
                    <td className="py-2 pr-3">
                      <span className={cn(
                        "rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase",
                        p.role === "ORG_ADMIN" ? "border-accent/40 text-accent" :
                        p.role === "MEMBER" ? "border-emerald-500/40 text-emerald-300" :
                        "border-white/15 text-ink-faint"
                      )}>
                        {p.role}
                      </span>
                    </td>
                    <td className="py-2 pr-3 text-ink-muted">{p.section}</td>
                    <td className="py-2 pr-3 text-emerald-300">{p.canSee}</td>
                    <td className="py-2 text-ink-faint">{p.cannotSee}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardBody>
      </Card>

      {/* Admin access audit log */}
      <Card>
        <CardHeader>
          <CardTitle>Admin Access Log</CardTitle>
          <span className="text-[11px] text-ink-faint">
            Every admin access to member data is recorded here
          </span>
        </CardHeader>
        <CardBody className="space-y-1">
          {adminViews.length === 0 && (
            <p className="text-sm text-ink-faint">No admin access events logged yet.</p>
          )}
          {adminViews.map((v) => (
            <div key={v.id} className="flex items-center gap-3 glass-sub rounded px-3 py-2 text-[11px]">
              <span className="text-accent">{v.admin_email || "system"}</span>
              <span className="text-ink-muted">{v.action}</span>
              <span className="text-ink-faint">{v.resource}</span>
              <span className="ml-auto text-ink-faint">{new Date(v.created_at).toLocaleString()}</span>
            </div>
          ))}
        </CardBody>
      </Card>
    </div>
  );
}

