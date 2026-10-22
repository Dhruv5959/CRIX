import { useEffect, useMemo, useRef, useState } from "react";
import ForceGraph2D from "react-force-graph-2d";
import { api } from "@/lib/api";
import type { GraphPayload } from "@/lib/types";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/card";
import { ProvenanceBadge } from "@/components/ui/badge";

export default function GraphPage() {
  const [graph, setGraph] = useState<GraphPayload | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(800);

  useEffect(() => {
    api.graph().then(setGraph).catch(() => setGraph(null));
  }, []);

  useEffect(() => {
    if (!containerRef.current) return;
    const observer = new ResizeObserver((entries) => {
      setWidth(entries[0].contentRect.width);
    });
    observer.observe(containerRef.current);
    return () => observer.disconnect();
  }, []);

  const data = useMemo(() => {
    if (!graph) return { nodes: [], links: [] };
    return {
      nodes: graph.nodes.map((n) => ({ ...n })),
      links: graph.edges.map((e) => ({ source: e.source, target: e.target, weight: e.weight })),
    };
  }, [graph]);

  if (!graph) return <div className="text-sm text-ink-faint">Loading dependency graph…</div>;

  return (
    <div className="space-y-6 animate-fade-in">
      <header className="flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-ink">Account Dependency Graph</h1>
          <p className="mt-1 text-sm text-ink-muted">
            Curated recovery/OAuth relationships. Ranks which account causes the most cascading
            damage if compromised. NetworkX, static data — not auto-discovered.
          </p>
        </div>
        <ProvenanceBadge provenance="CURATED" />
      </header>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-[1fr_340px]">
        <Card className="overflow-hidden">
          <CardBody className="p-0">
            <div ref={containerRef} className="h-[560px] w-full bg-black/25">
              <ForceGraph2D
                graphData={data}
                width={width}
                height={560}
                backgroundColor="transparent"
                nodeRelSize={6}
                linkColor={() => "rgba(148,163,184,0.25)"}
                linkWidth={(l: { weight?: number }) => (l.weight ?? 1) * 1.2}
                linkDirectionalArrowLength={4}
                linkDirectionalArrowRelPos={1}
                nodeCanvasObject={(node: { id: string; x?: number; y?: number; connected?: boolean }, ctx, scale) => {
                  const radius = (node.connected ? 7 : 4.5) / scale;
                  ctx.beginPath();
                  ctx.arc(node.x!, node.y!, radius, 0, 2 * Math.PI);
                  ctx.fillStyle = node.connected ? "#22d3ee" : "#334155";
                  ctx.fill();
                  if (selected === node.id) {
                    ctx.strokeStyle = "#67e8f9";
                    ctx.lineWidth = 2 / scale;
                    ctx.stroke();
                  }
                  if (scale > 0.9) {
                    ctx.font = `${11 / scale}px Inter, sans-serif`;
                    ctx.fillStyle = node.connected ? "#e6ecf5" : "#94a3b8";
                    ctx.textAlign = "center";
                    ctx.fillText(node.id, node.x!, node.y! + radius + 10 / scale);
                  }
                }}
                onNodeClick={(node: { id: string }) => setSelected(node.id)}
              />
            </div>
          </CardBody>
        </Card>

        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Centrality Ranking</CardTitle>
              <span className="text-[11px] text-ink-faint">weighted PageRank</span>
            </CardHeader>
            <CardBody className="space-y-2">
              {graph.ranking.slice(0, 12).map((r) => (
                <button
                  key={r.service}
                  onClick={() => setSelected(r.service)}
                  className={`flex w-full items-center justify-between rounded-lg border px-3 py-2 text-left transition-colors ${
                    selected === r.service
                      ? "border-accent/50 bg-accent/5"
                      : "border-white/10 bg-white/[0.04] hover:border-white/25"
                  }`}
                >
                  <div>
                    <div className="text-sm text-ink">
                      <span className="mr-2 font-mono text-[11px] text-ink-faint">#{r.rank}</span>
                      {r.service}
                    </div>
                    <div className="text-[11px] text-ink-faint">
                      {r.dependents.length} dependent{r.dependents.length === 1 ? "" : "s"}
                    </div>
                  </div>
                  <span className="font-mono text-[11px] text-accent">{r.pagerank.toFixed(4)}</span>
                </button>
              ))}
            </CardBody>
          </Card>

          {selected && <EdgeDetail graph={graph} service={selected} />}
        </div>
      </div>
    </div>
  );
}

function EdgeDetail({ graph, service }: { graph: GraphPayload; service: string }) {
  const outgoing = graph.edges.filter((e) => e.source === service);
  const incoming = graph.edges.filter((e) => e.target === service);
  return (
    <Card>
      <CardHeader>
        <CardTitle>{service}</CardTitle>
      </CardHeader>
      <CardBody className="space-y-3 text-xs">
        <div>
          <div className="label-eyebrow mb-1.5">Recovery routes out ({outgoing.length})</div>
          {outgoing.length === 0 && <span className="text-ink-faint">none</span>}
          {outgoing.map((e, i) => (
            <div key={i} className="mb-1.5 rounded border border-white/10 bg-white/[0.04] p-2">
              <div className="flex items-center justify-between">
                <span className="text-ink">→ {e.target}</span>
                <span className="glass-chip rounded border px-1.5 py-0.5 text-[10px] text-ink-faint">
                  {e.relationship_type}
                </span>
              </div>
              <p className="mt-1 text-[11px] text-ink-faint">{e.description}</p>
              <p className="mt-1 text-[10px] text-ink-faint">source: {e.source_ref}</p>
            </div>
          ))}
        </div>
        <div>
          <div className="label-eyebrow mb-1.5">Incoming dependencies ({incoming.length})</div>
          {incoming.length === 0 && <span className="text-ink-faint">none</span>}
          {incoming.map((e, i) => (
            <div key={i} className="mb-1 text-ink-muted">
              ← {e.source} <span className="text-ink-faint">({e.relationship_type})</span>
            </div>
          ))}
        </div>
      </CardBody>
    </Card>
  );
}