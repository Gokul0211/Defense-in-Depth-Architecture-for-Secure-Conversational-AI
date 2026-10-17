"use client";
import { useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { MagnifyingGlass } from "@phosphor-icons/react";
import { api } from "@/lib/api/client";
import { useConsole } from "@/lib/state/console-store";
import type { DemoScenario } from "@/lib/api/types";
import clsx from "clsx";

interface Cmd { id: string; label: string; hint: string; run: () => void | Promise<void> }

export function CommandPalette({ onScenario, onReset }: { onScenario: (sid: string) => void; onReset: () => void }) {
  const dlg = useRef<HTMLDialogElement>(null);
  const inp = useRef<HTMLInputElement>(null);
  const router = useRouter();
  const [q, setQ] = useState("");
  const [i, setI] = useState(0);
  const [scenarios, setScenarios] = useState<DemoScenario[]>([]);
  const [msg, setMsg] = useState<string | null>(null);
  const setFilters = useConsole((s) => s.setFilters);
  const setReplay = useConsole((s) => s.setReplayTs);
  const events = useConsole((s) => s.events);
  const conn = useConsole((s) => s.connection);
  const density = useConsole((s) => s.density);
  const setDensity = useConsole((s) => s.setDensity);
  const grouped = useConsole((s) => s.grouped);
  const setGrouped = useConsole((s) => s.setGrouped);

  const close = () => dlg.current?.close();
  const open = () => { setQ(""); setI(0); setMsg(null); if (!dlg.current?.open) dlg.current?.showModal(); setTimeout(() => inp.current?.focus(), 0); if (!scenarios.length && conn === "live") api.demos().then((d) => setScenarios(d.scenarios)).catch(() => {}); };

  useEffect(() => {
    const k = (e: KeyboardEvent) => { if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); dlg.current?.open ? close() : open(); } };
    window.addEventListener("keydown", k); return () => window.removeEventListener("keydown", k);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scenarios.length, conn]);

  const cmds = useMemo<Cmd[]>(() => [
    ...scenarios.map<Cmd>((s) => ({ id: `run-${s.id}`, label: `Run scenario: ${s.name}`, hint: (s.layers ?? []).join(" "), run: async () => { try { const r = await api.runDemo(s.id); onScenario(r.session_id); close(); } catch (e) { setMsg(e instanceof Error ? e.message : "Could not start the scenario."); } } })),
    ...["L1", "L2", "L3", "L4", "L5", "TIB"].map<Cmd>((l) => ({ id: `f-${l}`, label: `Filter stream: ${l}`, hint: "filter", run: () => { setFilters({ layer: l }); close(); } })),
    { id: "f-clear", label: "Clear filters", hint: "filter", run: () => { setFilters({ layer: "", severity: "", action: "" }); close(); } },
    { id: "f-blocked", label: "Show only blocked", hint: "filter", run: () => { setFilters({ action: "BLOCKED" }); close(); } },
    { id: "density", label: density === "compact" ? "Use comfortable rows" : "Use compact rows", hint: "density", run: () => { setDensity(density === "compact" ? "comfortable" : "compact"); close(); } },
    { id: "group", label: grouped ? "Ungroup the stream" : "Group the stream by session", hint: "stream", run: () => { setGrouped(!grouped); close(); } },
    { id: "live", label: "Back to live", hint: "replay", run: () => { setReplay(null); close(); } },
    ...(events[0] ? [{ id: "latest", label: "Open the latest session", hint: events[0].session_id.slice(0, 12), run: () => { router.push(`/console/sessions/${encodeURIComponent(events[0].session_id)}`); close(); } } as Cmd] : []),
    { id: "reset", label: "Reset the console", hint: "clears the backend", run: () => { close(); onReset(); } },
  ], [scenarios, events, onScenario, onReset, router, setFilters, setReplay, density, setDensity, grouped, setGrouped]);

  const shown = cmds.filter((c) => (c.label + " " + c.hint).toLowerCase().includes(q.toLowerCase()));
  useEffect(() => setI(0), [q]);

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") { e.preventDefault(); setI((x) => Math.min(shown.length - 1, x + 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setI((x) => Math.max(0, x - 1)); }
    else if (e.key === "Enter") { e.preventDefault(); shown[i]?.run(); }
  };

  return (
    <>
      <button onClick={open} className="num hidden h-9 items-center gap-2 rounded-full border border-line px-3 text-xs text-bone-2 hover:bg-ink-2 hover:text-bone md:flex" aria-label="Open command palette">
        <MagnifyingGlass size={14} aria-hidden />Commands<kbd className="ml-1 bg-ink-3 px-1.5 py-0.5 text-[0.65rem] text-bone-3">Ctrl K</kbd>
      </button>
      <dialog ref={dlg} onClick={(e) => { if (e.target === dlg.current) close(); }} aria-label="Command palette"
        className="m-auto mt-[12vh] w-[min(34rem,94vw)] rounded-[var(--radius-panel)] border border-line-strong bg-ink-1 p-0 text-bone backdrop:bg-black/60 backdrop:backdrop-blur-sm">
        <div className="flex items-center gap-3 border-b border-line px-4">
          <MagnifyingGlass size={16} className="text-bone-3" aria-hidden />
          <input ref={inp} value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={onKey} placeholder="Type a command" aria-label="Command" className="h-12 flex-1 bg-transparent text-sm outline-none placeholder:text-bone-3" />
        </div>
        {msg && <p role="alert" className="border-b border-line px-4 py-2 text-sm text-signal">{msg}</p>}
        <ul className="pane-scroll max-h-80 overflow-auto p-2" role="listbox">
          {shown.length === 0 && <li className="p-4 text-sm text-bone-3">No matching command.</li>}
          {shown.map((c, n) => (
            <li key={c.id} role="option" aria-selected={n === i}>
              <button onClick={() => c.run()} onPointerEnter={() => setI(n)} className={clsx("flex w-full items-center justify-between gap-3 rounded-[var(--radius-input)] px-3 py-2.5 text-left text-sm", n === i ? "bg-ink-3 text-bone" : "text-bone-2")}>
                <span>{c.label}</span><span className="num text-xs text-bone-3">{c.hint}</span>
              </button>
            </li>
          ))}
        </ul>
      </dialog>
    </>
  );
}
