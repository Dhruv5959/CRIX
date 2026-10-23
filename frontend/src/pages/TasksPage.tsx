import { useEffect, useState } from "react";
import { CheckCircle, Circle, Clock, RefreshCw, RotateCcw, ShieldCheck, XCircle } from "lucide-react";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import type { RemediationTask, RemediationTaskDetail, TaskStatus } from "@/lib/types";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ProvenanceBadge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

const STATUS_CONFIG: Record<TaskStatus, { label: string; color: string; icon: React.ComponentType<{ size?: number; className?: string }> }> = {
  OPEN: { label: "Open", color: "text-amber-300 border-amber-500/40", icon: Circle },
  DONE: { label: "Done", color: "text-blue-300 border-blue-500/40", icon: Clock },
  VERIFIED_MODELED: { label: "Verified (Modeled)", color: "text-emerald-300 border-emerald-500/40", icon: CheckCircle },
  VERIFIED_OBSERVED: { label: "Verified (Observed)", color: "text-cyan-300 border-cyan-500/40", icon: ShieldCheck },
};

export default function TasksPage() {
  const { role } = useAuth();
  const isAdmin = role === "ORG_ADMIN";
  const canContribute = role === "ORG_ADMIN" || role === "MEMBER";
  const [tasks, setTasks] = useState<RemediationTask[]>([]);
  const [selected, setSelected] = useState<RemediationTaskDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = async () => {
    try {
      setTasks(await api.listTasks());
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load tasks");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const selectTask = async (id: string) => {
    try {
      setSelected(await api.getTask(id));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load task");
    }
  };

  const complete = async (id: string) => {
    setBusy(true);
    try {
      await api.completeTask(id);
      await load();
      await selectTask(id);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to complete task");
    } finally {
      setBusy(false);
    }
  };

  const verify = async (id: string, method: string) => {
    setBusy(true);
    try {
      await api.verifyTask(id, { method, attested: true });
      await load();
      await selectTask(id);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Verification failed: " + (e instanceof Error ? e.message : ""));
    } finally {
      setBusy(false);
    }
  };

  const reopen = async (id: string) => {
    setBusy(true);
    try {
      await api.reopenTask(id, "Reopened from UI");
      await load();
      await selectTask(id);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to reopen task");
    } finally {
      setBusy(false);
    }
  };

  if (loading) return <div className="text-sm text-ink-faint">Loading tasks…</div>;

  return (
    <div className="space-y-6 animate-fade-in">
      <header>
        <h1 className="text-2xl font-semibold text-ink">Task Board</h1>
        <p className="mt-1 text-sm text-ink-muted">
          Remediation tasks with a 4-state lifecycle: Open → Done → Verified (Modeled or Observed).
        </p>
      </header>

      {error && (
        <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-300">
          {error}
          <button className="ml-2 underline" onClick={() => setError(null)}>dismiss</button>
        </div>
      )}

      {/* Kanban-style columns */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
        {(["OPEN", "DONE", "VERIFIED_MODELED", "VERIFIED_OBSERVED"] as TaskStatus[]).map((status) => {
          const config = STATUS_CONFIG[status];
          const StatusIcon = config.icon;
          const filtered = tasks.filter((t) => t.status === status);
          return (
            <div key={status} className="space-y-2">
              <div className={cn("flex items-center gap-2 text-xs font-semibold uppercase tracking-wide", config.color)}>
                <StatusIcon size={14} /> {config.label} ({filtered.length})
              </div>
              {filtered.map((t) => (
                <button
                  key={t.id}
                  onClick={() => selectTask(t.id)}
                  className={cn(
                    "w-full text-left glass-sub rounded-lg p-3 border transition-colors",
                    selected?.id === t.id ? "border-accent/50" : "border-transparent hover:border-white/10"
                  )}
                >
                  <div className="text-sm text-ink">{t.title}</div>
                  <div className="mt-1 text-[11px] text-ink-faint">
                    effort {t.effort} · {t.action_key}
                  </div>
                  {t.expected_reduction != null && t.expected_reduction > 0 && (
                    <div className="mt-0.5 text-[10px] text-emerald-300">
                      −{t.expected_reduction.toFixed(1)} expected reduction
                    </div>
                  )}
                </button>
              ))}
              {filtered.length === 0 && (
                <div className="glass-sub rounded-lg p-3 text-xs text-ink-faint text-center">
                  No tasks
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Task detail */}
      {selected && (
        <Card>
          <CardHeader>
            <CardTitle>{selected.title}</CardTitle>
            <ProvenanceBadge provenance="MODEL" />
          </CardHeader>
          <CardBody className="space-y-4">
            <p className="text-sm text-ink-muted">{selected.description}</p>

            <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
              <div>
                <div className="label-eyebrow">Status</div>
                <div className={cn("mt-1 text-sm font-semibold", STATUS_CONFIG[selected.status].color)}>
                  {STATUS_CONFIG[selected.status].label}
                </div>
              </div>
              <div>
                <div className="label-eyebrow">Effort</div>
                <div className="mt-1 font-mono text-sm text-ink">{selected.effort}</div>
              </div>
              <div>
                <div className="label-eyebrow">Expected reduction</div>
                <div className="mt-1 font-mono text-sm text-emerald-300">
                  {selected.expected_reduction != null ? `−${selected.expected_reduction.toFixed(2)}` : "—"}
                </div>
              </div>
              <div>
                <div className="label-eyebrow">Verification</div>
                <div className="mt-1 text-sm text-ink-muted">{selected.verification_method}</div>
              </div>
            </div>

            {selected.addresses.length > 0 && (
              <div>
                <div className="label-eyebrow">Addresses</div>
                <div className="mt-1 flex flex-wrap gap-1">
                  {selected.addresses.map((a) => (
                    <span key={a} className="rounded border border-white/15 bg-white/[0.06] px-2 py-0.5 text-[11px] text-ink-muted">
                      {a.replace(/_/g, " ")}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Actions */}
            <div className="flex flex-wrap gap-2 border-t border-white/10 pt-3">
              {selected.status === "OPEN" && canContribute && (
                <Button size="sm" variant="primary" onClick={() => complete(selected.id)} disabled={busy}>
                  <CheckCircle size={14} /> Mark complete (attestation)
                </Button>
              )}
              {selected.status === "DONE" && isAdmin && (
                <>
                  <Button size="sm" variant="primary" onClick={() => verify(selected.id, "VERIFIED_MODELED")} disabled={busy}>
                    <ShieldCheck size={14} /> Verify (modeled)
                  </Button>
                  <Button size="sm" onClick={() => verify(selected.id, "VERIFIED_OBSERVED")} disabled={busy}>
                    <ShieldCheck size={14} /> Verify (observed)
                  </Button>
                </>
              )}
              {selected.status !== "OPEN" && isAdmin && (
                <Button size="sm" variant="secondary" onClick={() => reopen(selected.id)} disabled={busy}>
                  <RotateCcw size={14} /> Reopen
                </Button>
              )}
            </div>

            {/* History */}
            {selected.history.length > 0 && (
              <div>
                <div className="label-eyebrow mb-2">Audit History</div>
                <div className="space-y-1">
                  {selected.history.map((h) => (
                    <div key={h.id} className="flex items-center gap-2 text-[11px] text-ink-faint glass-sub rounded px-2 py-1">
                      <span className="text-ink-muted">{h.from_status || "—"} → {h.to_status}</span>
                      <span className="text-ink-faint">{h.method}</span>
                      <span className={h.result === "PASS" ? "text-emerald-300" : h.result === "FAIL" ? "text-rose-300" : "text-ink-faint"}>
                        {h.result}
                      </span>
                      {h.model_version && <span className="font-mono">{h.model_version}</span>}
                      <span className="ml-auto">{new Date(h.created_at).toLocaleString()}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </CardBody>
        </Card>
      )}
    </div>
  );
}

