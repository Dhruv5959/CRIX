import { useEffect, useState } from "react";
import { Plus, Trash2, Box, ArrowRight } from "lucide-react";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import type { OrgAsset, AssetDependency } from "@/lib/types";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input, Label, Select } from "@/components/ui/input";
import { ProvenanceBadge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

const ASSET_TYPES = [
  "WORK_EMAIL", "WORKSPACE_IDENTITY", "CODE_REPOSITORY", "CLOUD_STORAGE",
  "CI_SYSTEM", "BUSINESS_APP", "DOMAIN", "SAAS_DEPENDENCY", "OTHER_COMPANY",
];

const RELATIONSHIP_TYPES = [
  "RESETS_PASSWORD", "HAS_ACCESS_TO", "DEPLOYS_TO", "USES", "DEPENDS_ON", "INTEGRATES_WITH",
];

export default function AssetsPage() {
  const { role } = useAuth();
  const isAdmin = role === "ORG_ADMIN";
  const [assets, setAssets] = useState<OrgAsset[]>([]);
  const [deps, setDeps] = useState<AssetDependency[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  // Create asset form
  const [newId, setNewId] = useState("");
  const [newType, setNewType] = useState(ASSET_TYPES[0]);
  const [newLabel, setNewLabel] = useState("");
  const [newCrit, setNewCrit] = useState(3);
  const [busy, setBusy] = useState(false);

  // Create dependency form
  const [depFrom, setDepFrom] = useState("");
  const [depTo, setDepTo] = useState("");
  const [depType, setDepType] = useState(RELATIONSHIP_TYPES[0]);

  const load = async () => {
    try {
      const [a, d] = await Promise.all([api.listAssets(), api.listDependencies()]);
      setAssets(a);
      setDeps(d);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load assets");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const createAsset = async () => {
    if (!newId || !newLabel) return;
    setBusy(true);
    setError(null);
    try {
      await api.createAsset({ asset_id: newId, asset_type: newType, label: newLabel, criticality: newCrit });
      setNewId(""); setNewLabel(""); setNewCrit(3);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to create asset");
    } finally {
      setBusy(false);
    }
  };

  const deleteAsset = async (id: string) => {
    try {
      await api.deleteAsset(id);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to delete asset");
    }
  };

  const createDep = async () => {
    if (!depFrom || !depTo) return;
    setBusy(true);
    setError(null);
    try {
      await api.createDependency({ from_asset_id: depFrom, to_asset_id: depTo, relationship_type: depType });
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to create dependency");
    } finally {
      setBusy(false);
    }
  };

  if (loading) return <div className="text-sm text-ink-faint">Loading assets…</div>;

  return (
    <div className="space-y-6 animate-fade-in">
      <header>
        <h1 className="text-2xl font-semibold text-ink">Asset Inventory</h1>
        <p className="mt-1 text-sm text-ink-muted">
          Company-owned assets and their declared dependencies. Criticality drives risk prioritization.
        </p>
      </header>

      {error && (
        <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-300">{error}</div>
      )}

      {/* Asset list */}
      <Card>
        <CardHeader>
          <CardTitle>Registered Assets ({assets.length})</CardTitle>
          <ProvenanceBadge provenance="USER_REPORTED" />
        </CardHeader>
        <CardBody className="space-y-2">
          {assets.length === 0 && (
            <p className="text-sm text-ink-faint">No assets registered yet. Add your first company asset below.</p>
          )}
          {assets.map((a) => (
            <div key={a.id} className="flex items-center justify-between glass-sub rounded-lg px-3 py-2">
              <div className="flex items-center gap-3">
                <Box size={14} className="text-accent" />
                <div>
                  <div className="text-sm text-ink">{a.label}</div>
                  <div className="text-[11px] text-ink-faint">
                    {a.asset_id} · {a.asset_type} · criticality {a.criticality}/5
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <span className={cn(
                  "rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase",
                  a.criticality >= 4 ? "border-rose-500/40 text-rose-300" :
                  a.criticality >= 3 ? "border-amber-500/40 text-amber-300" :
                  "border-emerald-500/40 text-emerald-300"
                )}>
                  {a.criticality >= 4 ? "HIGH" : a.criticality >= 3 ? "MEDIUM" : "LOW"}
                </span>
                {isAdmin && (
                  <button className="text-ink-faint hover:text-rose-300" onClick={() => deleteAsset(a.asset_id)} aria-label="delete">
                    <Trash2 size={14} />
                  </button>
                )}
              </div>
            </div>
          ))}
        </CardBody>
      </Card>

      {/* Dependencies */}
      <Card>
        <CardHeader>
          <CardTitle>Dependencies ({deps.length})</CardTitle>
        </CardHeader>
        <CardBody className="space-y-2">
          {deps.length === 0 && (
            <p className="text-sm text-ink-faint">No dependencies declared yet.</p>
          )}
          {deps.map((d) => (
            <div key={d.id} className="flex items-center gap-2 glass-sub rounded-lg px-3 py-2 text-xs">
              <span className="text-ink">{d.from_asset_id}</span>
              <ArrowRight size={12} className="text-ink-faint" />
              <span className="text-ink">{d.to_asset_id}</span>
              <span className="glass-chip rounded border px-1.5 py-0.5 text-[10px] uppercase text-accent">
                {d.relationship_type}
              </span>
              <span className="ml-auto text-ink-faint">{d.edge_source}</span>
            </div>
          ))}
        </CardBody>
      </Card>

      {/* Create asset form (admin only) */}
      {isAdmin && (
        <Card>
          <CardHeader><CardTitle>Register Asset</CardTitle></CardHeader>
          <CardBody className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <Label>Asset ID</Label>
                <Input value={newId} onChange={(e) => setNewId(e.target.value)} placeholder="work@company.com" />
              </div>
              <div>
                <Label>Label</Label>
                <Input value={newLabel} onChange={(e) => setNewLabel(e.target.value)} placeholder="Company work email" />
              </div>
              <div>
                <Label>Type</Label>
                <Select value={newType} onChange={(e) => setNewType(e.target.value)}>
                  {ASSET_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
                </Select>
              </div>
              <div>
                <Label>Criticality (1–5)</Label>
                <Input type="number" min={1} max={5} value={newCrit} onChange={(e) => setNewCrit(Number(e.target.value))} />
              </div>
            </div>
            <Button variant="primary" size="sm" onClick={createAsset} disabled={busy || !newId || !newLabel}>
              <Plus size={14} /> Register asset
            </Button>
          </CardBody>
        </Card>
      )}

      {/* Create dependency form (admin only) */}
      {isAdmin && assets.length >= 2 && (
        <Card>
          <CardHeader><CardTitle>Declare Dependency</CardTitle></CardHeader>
          <CardBody className="space-y-3">
            <div className="grid grid-cols-3 gap-3">
              <div>
                <Label>From asset</Label>
                <Select value={depFrom} onChange={(e) => setDepFrom(e.target.value)}>
                  <option value="">Select…</option>
                  {assets.map((a) => <option key={a.asset_id} value={a.asset_id}>{a.label}</option>)}
                </Select>
              </div>
              <div>
                <Label>Relationship</Label>
                <Select value={depType} onChange={(e) => setDepType(e.target.value)}>
                  {RELATIONSHIP_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
                </Select>
              </div>
              <div>
                <Label>To asset</Label>
                <Select value={depTo} onChange={(e) => setDepTo(e.target.value)}>
                  <option value="">Select…</option>
                  {assets.filter((a) => a.asset_id !== depFrom).map((a) => (
                    <option key={a.asset_id} value={a.asset_id}>{a.label}</option>
                  ))}
                </Select>
              </div>
            </div>
            <Button variant="primary" size="sm" onClick={createDep} disabled={busy || !depFrom || !depTo}>
              <Plus size={14} /> Declare dependency
            </Button>
          </CardBody>
        </Card>
      )}
    </div>
  );
}

