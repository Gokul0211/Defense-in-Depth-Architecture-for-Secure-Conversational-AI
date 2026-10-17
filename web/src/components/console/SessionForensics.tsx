"use client";
import Link from "next/link";
import { useEffect, useMemo, useRef, useState } from "react";
import { Pause, Play } from "@phosphor-icons/react";
import { Wordmark } from "@/components/brand/Wordmark";
import { Button } from "@/components/ui/Button";
import { InlineError } from "@/components/ui/InlineError";
import { Skeleton } from "@/components/ui/Skeleton";
import { SeverityTag } from "@/components/ui/SeverityTag";
import { ChainList } from "./DetailPanel";
import { Radar } from "./Radar";
import { api, API_URL, ApiError, OfflineError } from "@/lib/api/client";
import { isHot, reasonOf } from "@/lib/console-utils";
import { prefersReducedMotion } from "@/lib/animations/core";
import type { SessionState, ThreatEvent, Turn } from "@/lib/api/types";
import clsx from "clsx";

const TAIL = 22; // seconds after the last event so its arc fades out

function Drift({ turns }: { turns: Turn[] }) {
  if (turns.length === 0) return <p className="text-sm text-bone-3">No conversation turns recorded for this session.</p>;
  const W = 520, H = 150, pad = 28;
  const x = (i: number) => pad + (turns.length === 1 ? (W - 2 * pad) / 2 : (i / (turns.length - 1)) * (W - 2 * pad));
  const y = (v: number) => H - 22 - Math.min(1, Math.max(0, v)) * (H - 40);
  const d = turns.map((t, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(t.score).toFixed(1)}`).join(" ");
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full" role="img" aria-label={`Risk score by turn: ${turns.map((t) => t.score.toFixed(2)).join(", ")}`}>
      {[0, 0.5, 1].map((g) => <g key={g}><line x1={pad} x2={W - pad} y1={y(g)} y2={y(g)} stroke="var(--line-strong)" strokeDasharray="2 4" /><text x={0} y={y(g) + 4} fontSize="10" fill="var(--bone-3)" className="num">{g}</text></g>)}
      <path d={d} fill="none" stroke="var(--bone-2)" strokeWidth={1.5} />
      {turns.map((t, i) => <rect key={t.turn_number} x={x(i) - 4} y={y(t.score) - 4} width={8} height={8} fill={t.score >= 0.6 ? "var(--signal)" : "var(--bone)"} />)}
      <text x={W - pad} y={H - 4} textAnchor="end" fontSize="10" fill="var(--bone-3)" className="num">turn</text>
    </svg>
  );
}

export function SessionForensics({ id }: { id: string }) {
  const [s, setS] = useState<SessionState | null>(null);
  const [err, setErr] = useState<{ kind: "offline" | "missing" | "other"; msg: string } | null>(null);
  const [p, setP] = useState(1);        // replay position 0..1
  const [playing, setPlaying] = useState(false);
  const rt = useRef(0);

  useEffect(() => {
    let alive = true;
    api.session(id).then((r) => alive && setS(r)).catch((e) => {
      if (!alive) return;
      setErr(e instanceof OfflineError ? { kind: "offline", msg: `Backend not reachable at ${API_URL}. Start it with python main.py.` }
        : e instanceof ApiError && e.status === 404 ? { kind: "missing", msg: "That session is not in the backend. Sessions are kept in memory and cleared on reset or restart." }
        : { kind: "other", msg: e instanceof Error ? e.message : "Request failed." });
    });
    return () => { alive = false; };
  }, [id]);

  const sorted = useMemo<ThreatEvent[]>(() => (s ? [...s.events].sort((a, b) => b.ts - a.ts) : []), [s]);
  const t0 = sorted.length ? sorted[sorted.length - 1].ts : 0;
  const t1 = sorted.length ? sorted[0].ts : 0;
  const T = Math.max(1, t1 - t0 + TAIL);
  rt.current = t0 + p * T;

  // autoplay once the data arrives, unless motion is reduced
  const started = useRef(false);
  useEffect(() => { if (s && sorted.length && !started.current && !prefersReducedMotion()) { started.current = true; setP(0); setPlaying(true); } }, [s, sorted.length]);
  useEffect(() => {
    if (!playing) return;
    const dur = Math.min(30, Math.max(10, T));
    let raf = 0, last = performance.now();
    const tick = (now: number) => {
      const dt = (now - last) / 1000; last = now;
      setP((v) => { const n = v + dt / dur; if (n >= 1) { setPlaying(false); return 1; } return n; });
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [playing, T]);

  const nowT = t0 + p * T;
  const activeId = [...sorted].reverse().filter((e) => e.ts <= nowT).at(-1)?.event_id;
  const chain = (sorted.find((e) => e.event_id === activeId) ?? sorted[0])?.explanation?.chain ?? [];
  const clock = useRef(() => rt.current).current;

  return (
    <main id="main" tabIndex={-1} className="container-x pb-24 pt-6">
      <header className="flex items-center justify-between border-b border-line pb-4"><Link href="/" aria-label="DIDA, home"><Wordmark /></Link><Link href="/console" className="text-sm text-bone-2 hover:text-bone">Back to console</Link></header>
      <p className="num mt-8 text-sm text-signal">Session flight recorder</p>
      <h1 className="num mt-1 break-all text-2xl font-medium md:text-3xl">{id}</h1>
      {err && <div className="mt-6 max-w-xl"><InlineError title={err.kind === "offline" ? "Backend offline" : err.kind === "missing" ? "Session not found" : "Request failed"}>{err.msg}</InlineError></div>}
      {!s && !err && <div className="mt-8 space-y-3"><Skeleton className="h-8 w-64" /><Skeleton className="h-64" /></div>}
      {s && (
        <div className="mt-8 grid gap-10 lg:grid-cols-[1fr_1.1fr]">
          <div className="order-2 space-y-10 lg:order-1">
            <section aria-labelledby="st"><h2 id="st" className="text-lg font-semibold">How it ended</h2>
              <dl className="num mt-4 grid grid-cols-2 gap-4 text-sm sm:grid-cols-4">
                <div><dt className="text-bone-3">Risk</dt><dd className="mt-1"><SeverityTag severity={s.risk} /></dd></div>
                <div><dt className="text-bone-3">Overall</dt><dd className="mt-1 text-lg">{s.overall.toFixed(3)}</dd></div>
                <div><dt className="text-bone-3">Turns</dt><dd className="mt-1 text-lg">{s.turn_count}</dd></div>
                <div><dt className="text-bone-3">State</dt><dd className={clsx("mt-1 text-lg", s.terminated && "text-signal")}>{s.terminated ? "Terminated" : "Active"}</dd></div>
              </dl>
              {s.terminated && <p className="mt-4 text-sm text-bone-2">Termination reason: <span className="text-bone">{s.termination_reason}</span></p>}
            </section>
            <section aria-labelledby="dr"><h2 id="dr" className="text-lg font-semibold">Risk by turn</h2><div className="mt-4"><Drift turns={s.turns} /></div></section>
            <section aria-labelledby="ev"><h2 id="ev" className="text-lg font-semibold">Events</h2>
              {sorted.length === 0 ? <p className="mt-3 text-sm text-bone-3">No events recorded.</p> : (
                <ol className="mt-4 divide-y divide-line">{[...sorted].reverse().map((e) => (
                  <li key={e.event_id} className={clsx("grid grid-cols-[2.2rem_1fr_auto] items-start gap-3 py-3 text-sm transition-opacity", e.ts > nowT ? "opacity-35" : "opacity-100", e.event_id === activeId && "bg-ink-2")}>
                    <span className="num px-1 text-signal">{e.layer}</span>
                    <span><span className="block text-bone">{e.threat_type}</span><span className="mt-0.5 block text-bone-2">{reasonOf(e)}</span></span>
                    <span className="flex items-center gap-2"><SeverityTag severity={e.severity} blocked={e.action === "BLOCKED"} />{isHot(e) && <span className="sr-only-text">high risk</span>}</span>
                  </li>
                ))}</ol>)}
            </section>
            <section aria-labelledby="l4"><h2 id="l4" className="text-lg font-semibold">Tool calls (L4)</h2>
              {s.l4_calls.length === 0 ? <p className="mt-3 text-sm text-bone-3">No tool calls audited in this session.</p> : (
                <ul className="mt-4 space-y-3">{s.l4_calls.map((c, i) => (
                  <li key={i} className="surface-1 p-4 text-sm"><p className="num flex flex-wrap gap-x-4"><span className="text-bone">{String(c.tool_name)}</span><span className={c.should_execute ? "text-bone-2" : "text-signal"}>{c.should_execute ? "executed" : "refused"}</span><span className="text-bone-3">score {Number(c.score).toFixed(2)}</span></p><p className="mt-1 text-bone-2">{String(c.reason ?? "")}</p></li>
                ))}</ul>)}
            </section>
          </div>

          <div className="order-1 lg:order-2">
            <div className="lg:sticky lg:top-6">
              <div className="surface-1 relative aspect-square max-h-[70vh] w-full overflow-hidden">
                <Radar events={sorted} clock={clock} className="absolute inset-0" />
                <span className="num absolute left-3 top-3 rounded-full bg-ink-3 px-3 py-1 text-xs text-bone-2">Replay of recorded events, not live</span>
              </div>
              <div className="mt-3 flex items-center gap-3">
                <Button size="sm" variant="secondary" onClick={() => { if (p >= 1) setP(0); setPlaying((v) => !v); }} aria-label={playing ? "Pause replay" : "Play replay"}>
                  {playing ? <Pause size={14} weight="fill" aria-hidden /> : <Play size={14} weight="fill" aria-hidden />}{playing ? "Pause" : p >= 1 ? "Replay" : "Play"}
                </Button>
                <input type="range" min={0} max={1} step={0.001} value={p} onChange={(e) => { setPlaying(false); setP(Number(e.target.value)); }} aria-label="Replay position" className="h-11 flex-1 cursor-pointer accent-[var(--signal)]" />
              </div>
              <div className="mt-6"><h2 className="mb-3 text-sm font-medium text-bone-2">Explanation chain at this moment</h2><ChainList chain={chain} /></div>
            </div>
          </div>
        </div>
      )}
    </main>
  );
}
