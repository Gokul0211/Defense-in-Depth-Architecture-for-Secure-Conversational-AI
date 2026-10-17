"use client";
import Link from "next/link";
import { useEffect, useMemo, useRef, useState } from "react";
import { Wordmark } from "@/components/brand/Wordmark";
import { Button } from "@/components/ui/Button";
import { ScenarioMenu } from "./ScenarioMenu";
import { CommandPalette } from "./CommandPalette";
import { useConsole } from "@/lib/state/console-store";
import { api } from "@/lib/api/client";
import { motion, prefersReducedMotion } from "@/lib/animations/core";

/** Counter that ticks to its new value instead of jumping. */
function Odometer({ value }: { value: number }) {
  const ref = useRef<HTMLSpanElement>(null);
  const cur = useRef({ v: value });
  useEffect(() => {
    const el = ref.current; if (!el) return;
    if (prefersReducedMotion()) { el.textContent = String(value); cur.current.v = value; return; }
    const t = motion.to(cur.current, { v: value, duration: 0.6, ease: "power2.out", onUpdate: () => { el.textContent = String(Math.round(cur.current.v)); } });
    return () => { t.kill(); };
  }, [value]);
  return <span ref={ref}>{value}</span>;
}

export function TopBar({ onScenario }: { onScenario: (sid: string) => void }) {
  const stats = useConsole((s) => s.stats);
  const conn = useConsole((s) => s.connection);
  const retryAt = useConsole((s) => s.retryAt);
  const events = useConsole((s) => s.events);
  const [left, setLeft] = useState(0);
  const [now, setNow] = useState(() => Date.now() / 1000);
  const dlg = useRef<HTMLDialogElement>(null);
  useEffect(() => { if (conn !== "disconnected" || !retryAt) return; const tick = () => setLeft(Math.max(0, Math.ceil((retryAt - Date.now()) / 1000))); tick(); const id = setInterval(tick, 500); return () => clearInterval(id); }, [conn, retryAt]);
  useEffect(() => { const id = setInterval(() => setNow(Date.now() / 1000), 2000); return () => clearInterval(id); }, []);

  const lastMinute = useMemo(() => events.filter((e) => e.action === "BLOCKED" && now - e.ts < 60).length, [events, now]);
  const label = conn === "live" ? "Live" : conn === "connecting" ? "Connecting" : `Disconnected${left ? `, retry in ${left}s` : ""}`;
  const counts = stats.counts;
  const askReset = () => dlg.current?.showModal();

  return (
    <header className="flex flex-wrap items-center gap-x-6 gap-y-2 border-b border-line px-4 py-2.5">
      <Link href="/" aria-label="DIDA, home" className="rounded-full"><Wordmark /></Link>
      <p className="num flex items-center gap-2 text-xs" role="status"><span aria-hidden className="inline-block size-2" style={{ background: conn === "live" ? "var(--signal)" : "var(--bone-3)" }} />{label}</p>
      <dl className="num ml-auto flex flex-wrap gap-x-5 gap-y-1 text-xs text-bone-2">
        <div className="flex gap-1.5"><dt>Sessions</dt><dd className="text-bone"><Odometer value={stats.active_sessions} /></dd></div>
        <div className="flex gap-1.5"><dt>Blocked</dt><dd className="text-bone"><Odometer value={stats.blocked} /></dd></div>
        <div className="flex gap-1.5"><dt>Blocked, last 60s</dt><dd className="text-signal"><Odometer value={lastMinute} /></dd></div>
        {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((k) => <div key={k} className="hidden gap-1.5 lg:flex"><dt>{k}</dt><dd className="text-bone"><Odometer value={counts[k] ?? 0} /></dd></div>)}
      </dl>
      <div className="flex items-center gap-2">
        <CommandPalette onScenario={onScenario} onReset={askReset} />
        <ScenarioMenu online={conn === "live"} onStarted={onScenario} />
        <Button size="sm" variant="ghost" disabled={conn !== "live"} onClick={askReset}>Reset</Button>
      </div>
      <dialog ref={dlg} className="surface-2 m-auto max-w-sm border border-line-strong p-6 text-bone backdrop:bg-black/60" aria-labelledby="reset-t">
        <h2 id="reset-t" className="text-lg font-semibold">Reset the console?</h2>
        <p className="mt-2 text-sm text-bone-2">This clears every event and session on the backend, for all connected clients.</p>
        <div className="mt-6 flex justify-end gap-2">
          <Button variant="ghost" size="sm" onClick={() => dlg.current?.close()}>Cancel</Button>
          <Button size="sm" onClick={async () => { await api.reset().catch(() => {}); dlg.current?.close(); }}>Reset</Button>
        </div>
      </dialog>
    </header>
  );
}
