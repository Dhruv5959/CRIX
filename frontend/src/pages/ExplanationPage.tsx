import { useEffect, useState } from "react";
import { CheckCircle2, Link2, ShieldAlert, Sparkles } from "lucide-react";
import { api } from "@/lib/api";
import type { Explanation } from "@/lib/types";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/card";
import { ProvenanceBadge } from "@/components/ui/badge";

export default function ExplanationPage() {
  const [explanation, setExplanation] = useState<Explanation | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.explanation().then(setExplanation).catch((e) => setError(e.message));
  }, []);

  if (error) {
    return <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-300">{error}</div>;
  }
  if (!explanation) return <div className="text-sm text-ink-faint">Building explanation…</div>;

  return (
    <div className="space-y-6 animate-fade-in">
      <header className="flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-ink">GraphRAG Explanation</h1>
          <p className="mt-1 text-sm text-ink-muted">
            Every security claim is grounded in the curated knowledge graph or in CRIX's own engine
            output. GraphRAG explains — it never computes risk.
          </p>
        </div>
        <div
          className={`flex items-center gap-2 rounded-lg border px-3 py-1.5 text-xs ${
            explanation.grounded ? "border-emerald-500/40 text-emerald-300" : "border-amber-500/40 text-amber-300"
          }`}
        >
          {explanation.grounded ? <CheckCircle2 size={14} /> : <ShieldAlert size={14} />}
          {explanation.grounded ? "Grounded — all claims cited" : "Unsupported claims detected"}
        </div>
      </header>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Sparkles size={15} className="text-accent" />
            <CardTitle>Summary</CardTitle>
          </div>
          <ProvenanceBadge provenance="CURATED" />
        </CardHeader>
        <CardBody>
          <p className="text-sm leading-relaxed text-ink-muted">{explanation.summary}</p>
        </CardBody>
      </Card>

      {!explanation.grounded && (
        <Card className="border-amber-500/40">
          <CardHeader>
            <CardTitle className="text-amber-300">Unsupported claims</CardTitle>
          </CardHeader>
          <CardBody className="space-y-1">
            {explanation.unsupported_claims.map((c, i) => (
              <div key={i} className="text-xs text-amber-200">
                {c}
              </div>
            ))}
          </CardBody>
        </Card>
      )}

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Reasoning statements</CardTitle>
            <span className="text-[11px] text-ink-faint">each with citations</span>
          </CardHeader>
          <CardBody className="space-y-3">
            {explanation.statements.map((s, i) => (
              <div key={i} className="glass-sub rounded-lg p-3">
                <p className="text-sm text-ink-muted">{s.text}</p>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {s.citations.map((c) => (
                    <span
                      key={c}
                      className={`rounded border px-1.5 py-0.5 font-mono text-[10px] ${
                        c.startsWith("engine:")
                          ? "border-accent/40 text-accent"
                          : "border-violet-500/40 text-violet-300"
                      }`}
                    >
                      {c}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <Link2 size={15} className="text-accent" />
              <CardTitle>Retrieved evidence</CardTitle>
            </div>
            <span className="text-[11px] text-ink-faint">{explanation.citations.length} edges</span>
          </CardHeader>
          <CardBody className="space-y-2">
            {explanation.citations.map((c) => (
              <div key={c.edge_id} className="glass-sub rounded-lg p-3">
                <div className="flex items-center gap-2 text-xs">
                  <span className="text-ink">{c.from}</span>
                  <span className="glass-chip rounded border px-1.5 py-0.5 text-[10px] uppercase text-ink-faint">
                    {c.predicate}
                  </span>
                  <span className="text-ink">{c.to}</span>
                </div>
                <p className="mt-1.5 text-[11px] text-ink-faint">{c.evidence}</p>
                <p className="mt-1 text-[10px] text-ink-faint">source: {c.source}</p>
              </div>
            ))}
          </CardBody>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Sanitized context passed to GraphRAG</CardTitle>
          <span className="text-[11px] text-ink-faint">no secrets, tokens, or raw text</span>
        </CardHeader>
        <CardBody>
          <pre className="overflow-x-auto glass-inset rounded-lg p-4 font-mono text-[11px] leading-relaxed text-ink-faint">
            {JSON.stringify(explanation.context, null, 2)}
          </pre>
        </CardBody>
      </Card>
    </div>
  );
}