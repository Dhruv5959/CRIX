import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/card";
import { ProvenanceBadge } from "@/components/ui/badge";

interface KGNode {
  id: string;
  type: string;
  label: string;
  description: string;
  source: string;
}
interface KGEdge {
  id: string;
  from: string;
  to: string;
  predicate: string;
  evidence: string;
  source: string;
}
interface Rule {
  rule_id: string;
  title: string;
  correlation_type: string;
  predicates: string[];
  explanation: string;
}

const predicateColor: Record<string, string> = {
  prevents: "border-emerald-500/40 text-emerald-300",
  defeats: "border-rose-500/40 text-rose-300",
  enables: "border-amber-500/40 text-amber-300",
};

export default function KnowledgePage() {
  const [kg, setKg] = useState<{ nodes: KGNode[]; edges: KGEdge[] } | null>(null);
  const [rules, setRules] = useState<Rule[]>([]);
  const [engine, setEngine] = useState("");

  useEffect(() => {
    api.knowledgeGraph().then((r) => setKg({ nodes: r.nodes as KGNode[], edges: r.edges as KGEdge[] }));
    api.correlationRules().then((r) => {
      setRules(r.rules as Rule[]);
      setEngine(r.engine);
    });
  }, []);

  const labelOf = (id: string) => kg?.nodes.find((n) => n.id === id)?.label || id;

  return (
    <div className="space-y-6 animate-fade-in">
      <header>
        <h1 className="text-2xl font-semibold text-ink">Knowledge Base</h1>
        <p className="mt-1 text-sm text-ink-muted">
          The curated security knowledge graph (GraphRAG's only source of security facts) and the
          declarative correlation rules.
        </p>
      </header>

      <Card>
        <CardHeader>
          <CardTitle>Correlation rules</CardTitle>
          <span className="text-[11px] text-ink-faint">{engine}</span>
        </CardHeader>
        <CardBody className="space-y-3">
          {rules.map((r) => (
            <div key={r.rule_id} className="glass-sub rounded-lg p-3">
              <div className="flex flex-wrap items-center gap-2">
                {r.predicates.map((p) => (
                  <span key={p} className="glass-chip rounded border px-2 py-0.5 font-mono text-[10px] text-ink-muted">
                    {p}
                  </span>
                ))}
                <span className="text-ink-faint">→</span>
                <span className="text-sm text-ink">{r.title}</span>
                <span className="ml-auto glass-chip rounded border px-1.5 py-0.5 font-mono text-[10px] text-ink-faint">
                  {r.rule_id}
                </span>
              </div>
              <p className="mt-2 text-[11px] text-ink-faint">{r.explanation}</p>
            </div>
          ))}
        </CardBody>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Security knowledge graph</CardTitle>
          <ProvenanceBadge provenance="CURATED" />
        </CardHeader>
        <CardBody className="space-y-2">
          {kg?.edges.map((e) => (
            <div key={e.id} className="glass-sub rounded-lg p-3">
              <div className="flex flex-wrap items-center gap-2 text-xs">
                <span className="text-ink">{labelOf(e.from)}</span>
                <span className={`rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase ${predicateColor[e.predicate] || "border-white/15 text-ink-faint"}`}>
                  {e.predicate}
                </span>
                <span className="text-ink">{labelOf(e.to)}</span>
              </div>
              <p className="mt-1.5 text-[11px] text-ink-faint">{e.evidence}</p>
              <p className="mt-1 text-[10px] text-ink-faint">source: {e.source}</p>
            </div>
          ))}
        </CardBody>
      </Card>
    </div>
  );
}