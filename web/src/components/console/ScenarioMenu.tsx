"use client";
import { useEffect, useRef, useState } from "react";
import { Play, X } from "@phosphor-icons/react";
import clsx from "clsx";
import { Button } from "@/components/ui/Button";
import { InlineError } from "@/components/ui/InlineError";
import { SpotlightCard } from "@/components/animation/SpotlightCard";
import { motion, prefersReducedMotion } from "@/lib/animations/core";
import { api, ApiError } from "@/lib/api/client";
import type { DemoScenario } from "@/lib/api/types";

const ORDER = ["L1", "L2", "L3", "L4", "L5", "TIB"];

function LayerStrip({ layers }: { layers: string[] }) {
  return (
    <ul className="flex flex-wrap gap-1" aria-label={`Layers involved: ${layers.join(", ")}`}>
      {ORDER.map((l) => {
        const on = layers.includes(l);
        return <li key={l} className={clsx("num grid h-6 min-w-8 place-items-center rounded-[var(--radius-chip)] px-1.5 text-[0.68rem]", on ? "bg-signal font-medium text-ink-0" : "bg-ink-3 text-bone-3")}>{l}</li>;
      })}
    </ul>
  );
}

/** Opened from the top bar or the command palette. `openSignal` increments to open it. */
export function ScenarioMenu({ online, onStarted, openSignal = 0 }: { online: boolean; onStarted: (sessionId: string) => void; openSignal?: number }) {
  const dlg = useRef<HTMLDialogElement>(null);
  const grid = useRef<HTMLUListElement>(null);
  const [open, setOpen] = useState(false);
  const [list, setList] = useState<DemoScenario[]>([]);
  const [cool, setCool] = useState(5);
  const [until, setUntil] = useState(0);
  const [now, setNow] = useState(0);
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => { if (online && !list.length) api.demos().then((d) => { setList(d.scenarios); setCool(d.cooldown_seconds); }).catch(() => {}); }, [online, list.length]);
  useEffect(() => { if (until <= Date.now()) return; setNow(Date.now()); const id = setInterval(() => setNow(Date.now()), 250); return () => clearInterval(id); }, [until]);
  useEffect(() => {
    if (!open || !grid.current || prefersReducedMotion()) return;
    motion.fromTo(grid.current.children, { opacity: 0, y: 16 }, { opacity: 1, y: 0, duration: 0.5, stagger: 0.06, ease: "expo.out" });
  }, [open, list.length]);

  const show = () => { setErr(null); setOpen(true); if (!dlg.current?.open) dlg.current?.showModal(); };
  const hide = () => dlg.current?.close();
  useEffect(() => { if (openSignal > 0 && online) show(); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [openSignal]);
  const left = Math.max(0, Math.ceil((until - now) / 1000));

  const run = async (id: string) => {
    setErr(null); setBusy(id);
    try { const r = await api.runDemo(id); onStarted(r.session_id); setUntil(Date.now() + cool * 1000); setNow(Date.now()); hide(); }
    catch (e) {
      setErr(e instanceof ApiError ? e.message : "Could not start the scenario.");
      if (e instanceof ApiError && e.status === 429) { setUntil(Date.now() + cool * 1000); setNow(Date.now()); }
    } finally { setBusy(null); }
  };

  return (
    <>
      <Button size="sm" variant="secondary" onClick={show} disabled={!online}>
        <Play size={14} weight="fill" aria-hidden />Run scenario{left > 0 && <span className="num text-bone-3">{left}s</span>}
      </Button>
      <dialog ref={dlg} onClose={() => setOpen(false)} onClick={(e) => { if (e.target === dlg.current) hide(); }} aria-labelledby="scn-title"
        className="m-auto w-[min(56rem,94vw)] rounded-[var(--radius-panel)] border border-line-strong bg-ink-1 p-0 text-bone backdrop:bg-black/70 backdrop:backdrop-blur-sm">
        <div className="flex items-start justify-between gap-4 border-b border-line p-6">
          <div>
            <h2 id="scn-title" className="text-xl font-semibold tracking-tight">Run a scenario</h2>
            <p className="mt-1 max-w-[56ch] text-sm text-bone-2">Each one drives traffic through the backend. Watch the rings and the stream respond.</p>
          </div>
          <button onClick={hide} aria-label="Close" className="grid size-10 shrink-0 place-items-center rounded-full text-bone-2 hover:bg-ink-3 hover:text-bone"><X size={18} /></button>
        </div>
        {err && <div className="px-6 pt-4"><InlineError title={err} /></div>}
        <ul ref={grid} className="grid gap-3 p-6 sm:grid-cols-2">
          {list.map((s) => {
            const layers = s.layers ?? [];
            const wide = layers.filter((l) => l !== "TIB").length >= 5;
            const disabled = left > 0 || busy !== null;
            return (
              <li key={s.id} className={clsx(wide && "sm:col-span-2")}>
                <SpotlightCard className="h-full rounded-[var(--radius-panel)] bg-ink-2">
                  <button onClick={() => run(s.id)} disabled={disabled} className="flex h-full w-full flex-col gap-4 rounded-[var(--radius-panel)] p-5 text-left transition-opacity disabled:opacity-45">
                    <div className="flex items-start justify-between gap-3">
                      <h3 className="text-base font-semibold tracking-tight">{s.name}</h3>
                      {wide && <span className="num shrink-0 rounded-[var(--radius-chip)] bg-signal-dim px-2 py-0.5 text-[0.68rem] text-signal">Full run</span>}
                    </div>
                    <p className="max-w-[52ch] text-sm text-bone-2">{s.desc ?? s.description}</p>
                    <div className="mt-auto flex flex-wrap items-end justify-between gap-3">
                      <LayerStrip layers={layers} />
                      <span className="text-xs text-bone-3">{busy === s.id ? "Starting" : left > 0 ? `Ready in ${left}s` : s.scripted.length ? "Scripted scenario" : s.source ? `Replays a real item from ${s.source}` : ""}</span>
                    </div>
                  </button>
                </SpotlightCard>
              </li>
            );
          })}
          {!list.length && <li className="col-span-full p-6 text-center text-sm text-bone-3">Loading scenarios</li>}
        </ul>
      </dialog>
    </>
  );
}
