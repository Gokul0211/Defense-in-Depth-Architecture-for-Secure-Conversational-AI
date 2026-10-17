"use client";
import { useEffect, useMemo, useRef, useState } from "react";
import { CaretRight } from "@phosphor-icons/react";
import { SeverityTag } from "@/components/ui/SeverityTag";
import { EmptyState } from "@/components/ui/EmptyState";
import { Skeleton } from "@/components/ui/Skeleton";
import { useConsole } from "@/lib/state/console-store";
import { reasonOf } from "@/lib/console-utils";
import { motion, prefersReducedMotion } from "@/lib/animations/core";
import type { ThreatEvent } from "@/lib/api/types";
import clsx from "clsx";

const HEAD = 40;
const sel = "h-9 rounded-[var(--radius-input)] border border-line bg-ink-3 px-2 text-xs text-bone";
type Item = { kind: "head"; sid: string; count: number; blocked: number; open: boolean } | { kind: "ev"; e: ThreatEvent };

export function EventStream({ scripted }: { scripted: Set<string> }) {
  const events = useConsole((s) => s.events);
  const connection = useConsole((s) => s.connection);
  const selected = useConsole((s) => s.selectedEventId);
  const select = useConsole((s) => s.selectEvent);
  const f = useConsole((s) => s.filters);
  const setFilters = useConsole((s) => s.setFilters);
  const replayTs = useConsole((s) => s.replayTs);
  const density = useConsole((s) => s.density);
  const setDensity = useConsole((s) => s.setDensity);
  const grouped = useConsole((s) => s.grouped);
  const setGrouped = useConsole((s) => s.setGrouped);
  const box = useRef<HTMLDivElement>(null);
  const [top, setTop] = useState(0);
  const [h, setH] = useState(600);
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const seen = useRef(new Set<string>());
  const compact = density === "compact";
  const ROW = compact ? 38 : 64;

  const rows = useMemo(() => events.filter((e) =>
    (replayTs === null || e.ts <= replayTs) && (!f.layer || e.layer === f.layer) && (!f.severity || e.severity === f.severity) && (!f.action || e.action === f.action)), [events, f, replayTs]);

  const items = useMemo<Item[]>(() => {
    if (!grouped) return rows.map((e) => ({ kind: "ev", e }));
    const order: string[] = []; const by = new Map<string, ThreatEvent[]>();
    rows.forEach((e) => { if (!by.has(e.session_id)) { by.set(e.session_id, []); order.push(e.session_id); } by.get(e.session_id)!.push(e); });
    const out: Item[] = [];
    order.forEach((sid) => {
      const list = by.get(sid)!; const open = !collapsed.has(sid);
      out.push({ kind: "head", sid, count: list.length, blocked: list.filter((x) => x.action === "BLOCKED").length, open });
      if (open) list.forEach((e) => out.push({ kind: "ev", e }));
    });
    return out;
  }, [rows, grouped, collapsed]);

  // variable heights: group headers and rows
  const { offs, total } = useMemo(() => {
    const o: number[] = []; let y = 0;
    items.forEach((it) => { o.push(y); y += it.kind === "head" ? HEAD : ROW; });
    return { offs: o, total: y };
  }, [items, ROW]);

  useEffect(() => {
    const el = box.current; if (!el) return;
    const ro = new ResizeObserver(() => setH(el.clientHeight)); ro.observe(el); setH(el.clientHeight);
    return () => ro.disconnect();
  }, []);

  let start = 0; { let lo = 0, hi = offs.length - 1; while (lo < hi) { const m = (lo + hi + 1) >> 1; if (offs[m] <= top) lo = m; else hi = m - 1; } start = Math.max(0, lo - 3); }
  let end = start; while (end < items.length && offs[end] < top + h + 200) end++;

  useEffect(() => {
    const el = box.current; if (!el || prefersReducedMotion() || replayTs !== null) return;
    el.querySelectorAll<HTMLElement>("[data-row]").forEach((r) => {
      const id = r.dataset.id!; if (seen.current.has(id)) return; seen.current.add(id);
      if (seen.current.size < 2) return;
      motion.fromTo(r, { x: -16, opacity: 0 }, { x: 0, opacity: 1, duration: 0.3, ease: "expo.out" });
      if (r.dataset.blocked) motion.fromTo(r, { backgroundColor: "rgb(255 79 31 / .35)" }, { backgroundColor: "rgba(255,79,31,0)", duration: 1 });
    });
  }, [items, start, end, replayTs]);

  const evIdx = items.map((it, i) => (it.kind === "ev" ? i : -1)).filter((i) => i >= 0);
  const onKey = (e: React.KeyboardEvent) => {
    if (e.key !== "j" && e.key !== "k") return;
    const cur = evIdx.findIndex((i) => (items[i] as { e: ThreatEvent }).e.event_id === selected);
    const n = Math.min(evIdx.length - 1, Math.max(0, e.key === "j" ? cur + 1 : cur - 1));
    const it = items[evIdx[n]];
    if (it && it.kind === "ev") { select(it.e.event_id); const el = box.current; if (el) el.scrollTop = Math.max(0, offs[evIdx[n]] - h / 2); }
  };

  const toggle = "h-9 rounded-full border px-3 text-xs transition-colors";
  return (
    <div className="flex h-full min-h-0 flex-col" onKeyDown={onKey}>
      <div className="flex flex-wrap gap-2 border-b border-line p-3">
        <select aria-label="Filter by layer" className={sel} value={f.layer} onChange={(e) => setFilters({ layer: e.target.value })}><option value="">All layers</option>{["L1", "L2", "L3", "L4", "L5", "TIB"].map((x) => <option key={x}>{x}</option>)}</select>
        <select aria-label="Filter by severity" className={sel} value={f.severity} onChange={(e) => setFilters({ severity: e.target.value })}><option value="">All severities</option>{["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((x) => <option key={x}>{x}</option>)}</select>
        <select aria-label="Filter by action" className={sel} value={f.action} onChange={(e) => setFilters({ action: e.target.value })}><option value="">All actions</option>{["ALLOWED", "WARNED", "BLOCKED"].map((x) => <option key={x}>{x}</option>)}</select>
        <button aria-pressed={grouped} onClick={() => setGrouped(!grouped)} className={clsx(toggle, grouped ? "border-signal text-bone" : "border-line text-bone-2 hover:bg-ink-2")}>Group by session</button>
        <button aria-pressed={compact} onClick={() => setDensity(compact ? "comfortable" : "compact")} className={clsx(toggle, compact ? "border-signal text-bone" : "border-line text-bone-2 hover:bg-ink-2")}>Compact</button>
      </div>
      <div ref={box} onScroll={(e) => setTop(e.currentTarget.scrollTop)} className="pane-scroll relative min-h-0 flex-1 overflow-y-auto" role="listbox" aria-label="Threat events, newest first">
        {connection === "connecting" && rows.length === 0 ? (
          <div className="space-y-2 p-3">{Array.from({ length: 7 }).map((_, i) => <Skeleton key={i} className="h-14" />)}</div>
        ) : rows.length === 0 ? (
          <EmptyState title="No events yet">Run a scenario or send traffic through the proxy.</EmptyState>
        ) : (
          <div style={{ height: total, position: "relative" }}>
            {items.slice(start, end).map((it, i) => {
              const idx = start + i;
              if (it.kind === "head") {
                return (
                  <button key={`h-${it.sid}`} onClick={() => setCollapsed((c) => { const n = new Set(c); n.has(it.sid) ? n.delete(it.sid) : n.add(it.sid); return n; })} aria-expanded={it.open}
                    className="num absolute inset-x-0 flex items-center gap-2 border-b border-line bg-ink-2 px-3 text-left text-xs text-bone-2 hover:text-bone" style={{ top: offs[idx], height: HEAD }}>
                    <CaretRight size={12} className={clsx("transition-transform", it.open && "rotate-90")} aria-hidden />
                    <span className="min-w-0 flex-1 truncate text-bone">{it.sid}</span>
                    <span>{it.count} events</span>{it.blocked > 0 && <span className="text-signal">{it.blocked} blocked</span>}
                  </button>
                );
              }
              const e = it.e; const reason = reasonOf(e);
              return (
                <button key={e.event_id} data-row data-id={e.event_id} data-blocked={e.action === "BLOCKED" ? "1" : undefined} role="option" aria-selected={selected === e.event_id}
                  onClick={() => select(e.event_id)}
                  className={clsx("absolute inset-x-0 flex flex-col justify-center gap-1 border-b border-line px-3 text-left transition-colors hover:bg-ink-2", selected === e.event_id && "bg-ink-3", grouped && "pl-6")}
                  style={{ top: offs[idx], height: ROW }}>
                  <span className="num flex items-center gap-2 text-xs">
                    <span className="text-bone-3">{e.timestamp}</span>
                    <span className="text-signal">{e.layer}</span>
                    <span className="min-w-0 flex-1 truncate text-bone">{e.threat_type}</span>
                    <SeverityTag severity={e.severity} blocked={e.action === "BLOCKED"} />
                    <span className="w-9 text-right text-bone">{e.threat_score.toFixed(2)}</span>
                  </span>
                  {!compact && (
                    <span className="flex items-center gap-2 text-xs text-bone-2">
                      <span className="min-w-0 flex-1 truncate">{reason || "No explanation recorded."}</span>
                      {!grouped && <span className="num shrink-0 text-bone-3">{e.session_id.slice(0, 10)}{(scripted.has(e.session_id) || e.evidence?.demo !== undefined) && " · scenario"}</span>}
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
