"use client";
import { useEffect, useRef, useState } from "react";
import { EventStream } from "./EventStream";
import { SessionList } from "./SessionList";
import { DetailPanel } from "./DetailPanel";
import { Radar } from "./Radar";
import { Tabs, TabPanel } from "@/components/ui/Tabs";
import { useConsole } from "@/lib/state/console-store";
import { LAYER_NAMES, reasonOf } from "@/lib/console-utils";
import { motion, prefersReducedMotion } from "@/lib/animations/core";
import type { ThreatEvent } from "@/lib/api/types";

const PEEK = 112;   // px of the sheet visible when collapsed

/**
 * Phone layout: the radar fills the top, a draggable bottom sheet holds the feed. Collapsed it shows the
 * latest blocked event; drag the handle (or tap it) to open. New blocked events nudge the radar and, where
 * the device allows it, vibrate briefly.
 */
export function MobileConsole({ events, clock, dead, scripted }: { events: ThreatEvent[]; clock: () => number; dead: boolean; scripted: Set<string> }) {
  const sheet = useRef<HTMLDivElement>(null);
  const radar = useRef<HTMLDivElement>(null);
  const [tab, setTab] = useState<"stream" | "sessions" | "detail">("stream");
  const [heights, setHeights] = useState({ H: 600, mid: 0, closed: 0 });
  const pos = useRef(0);          // current translateY
  const selectedId = useConsole((s) => s.selectedEventId);
  const latestBlocked = events.find((e) => e.action === "BLOCKED") ?? events[0];

  // size the sheet and snap points from the container
  useEffect(() => {
    const el = sheet.current?.parentElement; if (!el) return;
    const measure = () => {
      const H = Math.round(el.clientHeight * 0.82);
      const next = { H, mid: Math.round(H * 0.42), closed: H - PEEK };
      setHeights(next);
      if (sheet.current) { pos.current = Math.min(pos.current || next.closed, next.closed); motion.set(sheet.current, { y: pos.current }); }
    };
    measure();
    const ro = new ResizeObserver(measure); ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const snapTo = (y: number) => { pos.current = y; if (sheet.current) motion.to(sheet.current, { y, duration: prefersReducedMotion() ? 0 : 0.4, ease: "power3.out", overwrite: true }); };
  const nearest = (y: number) => [0, heights.mid, heights.closed].reduce((a, b) => (Math.abs(b - y) < Math.abs(a - y) ? b : a));

  const drag = useRef<{ y0: number; p0: number; moved: boolean } | null>(null);
  const onDown = (e: React.PointerEvent) => { (e.currentTarget as Element).setPointerCapture(e.pointerId); drag.current = { y0: e.clientY, p0: pos.current, moved: false }; };
  const onMove = (e: React.PointerEvent) => {
    const d = drag.current; if (!d || !sheet.current) return;
    const dy = e.clientY - d.y0; if (Math.abs(dy) > 4) d.moved = true;
    const y = Math.min(heights.closed, Math.max(0, d.p0 + dy)); pos.current = y; motion.set(sheet.current, { y });
  };
  const onUp = () => {
    const d = drag.current; drag.current = null; if (!d) return;
    if (!d.moved) snapTo(pos.current > heights.mid + 20 ? heights.mid : pos.current > 20 ? 0 : heights.closed);   // tap cycles
    else snapTo(nearest(pos.current));
  };

  // selecting an event opens the detail view
  useEffect(() => { if (selectedId) { setTab("detail"); if (pos.current > heights.mid) snapTo(heights.mid); } /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [selectedId]);

  // blocked events: a small physical cue
  useEffect(() => useConsole.subscribe((st, prev) => {
    const e = st.lastEvent; if (!e || e === prev.lastEvent || e.action !== "BLOCKED") return;
    if (!prefersReducedMotion() && radar.current) motion.fromTo(radar.current, { x: -5 }, { x: 0, duration: 0.5, ease: "elastic.out(1, 0.25)" });
    if (typeof navigator !== "undefined" && "vibrate" in navigator && !prefersReducedMotion()) navigator.vibrate(30);
  }), []);

  return (
    <main id="main" tabIndex={-1} className="relative min-h-0 flex-1 overflow-hidden">
      <div ref={radar} className="absolute inset-x-2 top-2 bottom-[calc(18%+0.5rem)]">
        <div className="surface-1 relative size-full overflow-hidden">
          <Radar events={events} clock={clock} frozen={dead} className="absolute inset-0" />
          <span className="num absolute left-3 top-3 text-xs text-bone-3">{dead ? "Disconnected" : "Lights only on real events"}</span>
        </div>
      </div>
      <div ref={sheet} className="absolute inset-x-0 bottom-0 flex flex-col rounded-t-[20px] border-t border-line-strong bg-ink-1" style={{ height: heights.H, transform: `translateY(${heights.closed}px)`, touchAction: "none" }}>
        <div role="button" tabIndex={0} aria-label="Drag to open the feed" onPointerDown={onDown} onPointerMove={onMove} onPointerUp={onUp} onPointerCancel={onUp}
          onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); snapTo(pos.current > 20 ? 0 : heights.closed); } }}
          className="shrink-0 cursor-grab px-4 pb-3 pt-2" style={{ touchAction: "none" }}>
          <span aria-hidden className="mx-auto block h-1 w-10 rounded-full bg-line-strong" />
          {latestBlocked ? (
            <div className="mt-3 flex items-center gap-3 text-sm">
              <span className="num text-signal">{latestBlocked.layer}</span>
              <span className="min-w-0 flex-1"><span className="block truncate text-bone">{latestBlocked.threat_type}</span><span className="block truncate text-xs text-bone-2">{reasonOf(latestBlocked) || LAYER_NAMES[latestBlocked.layer]}</span></span>
              <span className="num text-xs text-bone-3">{latestBlocked.action === "BLOCKED" ? "latest blocked" : "latest"}</span>
            </div>
          ) : <p className="mt-3 text-sm text-bone-3">No events yet</p>}
        </div>
        <div className="min-h-0 flex-1 overflow-hidden border-t border-line" style={{ touchAction: "pan-y" }}>
          <Tabs tabs={[{ id: "stream", label: "Stream" }, { id: "sessions", label: "Sessions" }, { id: "detail", label: "Detail" }]} active={tab} onChange={(x) => setTab(x as typeof tab)} label="Feed" className="flex h-full min-h-0 flex-col">
            <TabPanel id="stream" active={tab} className="min-h-0 flex-1"><EventStream scripted={scripted} /></TabPanel>
            <TabPanel id="sessions" active={tab} className="pane-scroll min-h-0 flex-1 overflow-auto"><SessionList /></TabPanel>
            <TabPanel id="detail" active={tab} className="pane-scroll min-h-0 flex-1 overflow-auto"><DetailPanel /></TabPanel>
          </Tabs>
        </div>
      </div>
    </main>
  );
}
