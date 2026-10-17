"use client";
import { useRef, useState } from "react";
import { Play } from "@phosphor-icons/react";
import { Button } from "@/components/ui/Button";
import { InlineError } from "@/components/ui/InlineError";
import { Pipeline, type PipeState } from "./Pipeline";
import { api, ApiError } from "@/lib/api/client";
import { useThresholds } from "@/hooks/useThresholds";
import { POISONED_DOC } from "@/lib/content/samples";
import { toVerdict, type Tool, type Verdict } from "@/lib/verdict";
import { motion, prefersReducedMotion } from "@/lib/animations/core";
import { useEffect } from "react";
import clsx from "clsx";

interface Opt { id: Tool; layer: string; label: string; run: (t: string) => Promise<Record<string, unknown>> }
const OPTS: Opt[] = [
  { id: "l1", layer: "L1", label: "As a prompt", run: (t) => api.l1Scan(t) },
  { id: "ingest", layer: "L2", label: "As a document", run: (t) => api.ingest(t, "compare") },
  { id: "toolresp", layer: "L4", label: "As a tool result", run: (t) => api.toolResponse(t, `cmp_${Date.now().toString(36)}`) },
  { id: "output", layer: "L5", label: "As a model reply", run: (t) => api.outputScan(t) },
];
const PRESET = POISONED_DOC;

/** The same text, judged by different layers. Shows which door each layer would have stopped it at. */
export function CompareLayers({ online }: { online: boolean }) {
  const thresholds = useThresholds(online);
  const [text, setText] = useState(PRESET);
  const [picked, setPicked] = useState<Set<Tool>>(new Set(["l1", "ingest", "toolresp", "output"]));
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [res, setRes] = useState<Partial<Record<Tool, Verdict | string>> | null>(null);
  const [pipe, setPipe] = useState<PipeState>("idle");
  const grid = useRef<HTMLDivElement>(null);

  const run = async () => {
    setBusy(true); setErr(null); setRes(null); setPipe("running");
    const chosen = OPTS.filter((o) => picked.has(o.id));
    try {
      const out = await Promise.allSettled(chosen.map((o) => o.run(text)));
      const m: Partial<Record<Tool, Verdict | string>> = {};
      out.forEach((r, i) => { m[chosen[i].id] = r.status === "fulfilled" ? toVerdict(chosen[i].id, r.value, thresholds) : r.reason instanceof ApiError ? `${r.reason.message} (HTTP ${r.reason.status})` : "Request failed"; });
      setRes(m); setPipe("done");
    } catch (e) { setErr(e instanceof Error ? e.message : "Request failed."); setPipe("idle"); }
    finally { setBusy(false); }
  };

  useEffect(() => {
    if (!res || !grid.current || prefersReducedMotion()) return;
    const t = motion.fromTo(grid.current.children, { opacity: 0, y: 14 }, { opacity: 1, y: 0, duration: 0.5, stagger: 0.08, ease: "expo.out" });
    return () => { t.kill(); };
  }, [res]);

  const used = OPTS.filter((o) => picked.has(o.id)).map((o) => o.layer);
  const firstStop = OPTS.find((o) => { const v = res?.[o.id]; return v && typeof v !== "string" && v.decision === "BLOCKED"; })?.layer ?? null;

  return (
    <div>
      <Pipeline used={used} stopLayer={pipe === "done" ? firstStop : null} state={pipe} />
      <div className="mt-8 grid gap-8 lg:grid-cols-[1fr_1.4fr]">
        <div>
          <label htmlFor="cmp-text" className="text-sm font-medium">Text to judge</label>
          <textarea id="cmp-text" rows={6} value={text} onChange={(e) => setText(e.target.value)} className="num mt-2 w-full rounded-[var(--radius-input)] border border-line bg-ink-3 p-3 text-sm text-bone" />
          <fieldset className="mt-4"><legend className="text-sm font-medium">Judge it as</legend>
            <div className="mt-2 flex flex-wrap gap-2">
              {OPTS.map((o) => (
                <label key={o.id} className={clsx("flex h-11 cursor-pointer items-center gap-2 rounded-full border px-4 text-sm", picked.has(o.id) ? "border-signal text-bone" : "border-line text-bone-2")}>
                  <input type="checkbox" className="sr-only-text" checked={picked.has(o.id)} onChange={() => setPicked((p) => { const n = new Set(p); n.has(o.id) ? n.delete(o.id) : n.add(o.id); return n; })} />
                  <span className="num text-xs text-signal">{o.layer}</span>{o.label}
                </label>
              ))}
            </div>
          </fieldset>
          <p className="mt-3 text-sm text-bone-3">Each choice calls its real endpoint. Judging text as a document also stores it as a chunk on the backend.</p>
          <div className="mt-5"><Button onClick={run} disabled={!online || busy || !text.trim() || picked.size === 0}><Play size={16} weight="fill" aria-hidden />{busy ? "Running" : "Compare"}</Button></div>
          {err && <div className="mt-4"><InlineError title="Request failed">{err}</InlineError></div>}
        </div>
        <div aria-live="polite">
          {res ? (
            <div ref={grid} className="grid gap-3 sm:grid-cols-2">
              {OPTS.filter((o) => picked.has(o.id)).map((o) => {
                const v = res[o.id];
                if (typeof v === "string" || !v) return <div key={o.id} className="surface-1 p-5 text-sm"><p className="num text-signal">{o.layer}</p><p className="mt-2 text-bone-2">{v ?? "No result"}</p></div>;
                const hot = v.decision !== "ALLOWED";
                return (
                  <div key={o.id} className="surface-1 p-5">
                    <p className="flex items-center justify-between text-sm"><span className="text-bone-2"><span className="num text-signal">{o.layer}</span> {o.label.toLowerCase()}</span></p>
                    <p className={clsx("num mt-2 text-3xl font-medium", hot ? "text-signal" : "text-bone")}>{v.decision}</p>
                    {v.score !== null && <div className="mt-3"><div className="flex justify-between text-xs text-bone-2"><span>score</span><span className="num text-bone">{v.score.toFixed(3)}</span></div><div className="mt-1 h-1.5 bg-ink-3"><div className="h-full bg-signal" style={{ width: `${Math.min(100, Math.max(1, v.score * 100))}%` }} /></div></div>}
                    <p className="mt-3 text-sm text-bone-2">{v.reason || "No reason returned."}</p>
                  </div>
                );
              })}
            </div>
          ) : <div className="surface-1 grid min-h-56 place-items-center p-6 text-center text-sm text-bone-3">Run it to see how each layer judges the same text.</div>}
        </div>
      </div>
    </div>
  );
}
