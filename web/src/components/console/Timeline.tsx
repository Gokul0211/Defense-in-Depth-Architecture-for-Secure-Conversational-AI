"use client";
import { useEffect, useRef, useState } from "react";
import { useConsole } from "@/lib/state/console-store";
import { isHot } from "@/lib/console-utils";

const LANES = ["L1", "L2", "L3", "L4", "L5", "TIB"];
const WINDOW = 600;      // seconds of history shown
const LEFT = 34;

/** Per-layer activity lanes. Drag to scrub: the radar, stream and inspector replay that moment. */
export function Timeline() {
  const events = useConsole((s) => s.events);
  const replayTs = useConsole((s) => s.replayTs);
  const setReplay = useConsole((s) => s.setReplayTs);
  const ref = useRef<SVGSVGElement>(null);
  const [now, setNow] = useState(() => Date.now() / 1000);
  const dragging = useRef(false);

  useEffect(() => { const id = setInterval(() => setNow(Date.now() / 1000), 1000); return () => clearInterval(id); }, []);

  const end = now, start = now - WINDOW;
  const W = 1000, H = 132, laneH = (H - 18) / LANES.length;
  const x = (t: number) => LEFT + ((t - start) / WINDOW) * (W - LEFT - 8);

  const scrub = (clientX: number) => {
    const r = ref.current?.getBoundingClientRect(); if (!r) return;
    const px = ((clientX - r.left) / r.width) * W;
    const t = start + ((px - LEFT) / (W - LEFT - 8)) * WINDOW;
    if (t >= end - 8) setReplay(null); else setReplay(Math.max(start, t));
  };

  return (
    <div className="surface-1 p-3">
      <div className="mb-1 flex items-center justify-between text-xs text-bone-3">
        <span>Last 10 minutes. Drag to replay a moment.</span>
        {replayTs !== null && <button onClick={() => setReplay(null)} className="rounded-full bg-signal px-3 py-1 font-medium text-ink-0">Back to live</button>}
      </div>
      <svg ref={ref} viewBox={`0 0 ${W} ${H}`} className="h-28 w-full cursor-ew-resize touch-none select-none" role="slider" tabIndex={0}
        aria-label="Replay position" aria-valuemin={0} aria-valuemax={WINDOW} aria-valuenow={replayTs === null ? WINDOW : Math.round(replayTs - start)} aria-valuetext={replayTs === null ? "Live" : `${Math.round(end - replayTs)} seconds ago`}
        onPointerDown={(e) => { dragging.current = true; (e.target as Element).setPointerCapture?.(e.pointerId); scrub(e.clientX); }}
        onPointerMove={(e) => { if (dragging.current) scrub(e.clientX); }}
        onPointerUp={() => { dragging.current = false; }}
        onKeyDown={(e) => {
          const cur = replayTs ?? end;
          if (e.key === "ArrowLeft") { e.preventDefault(); setReplay(Math.max(start, cur - 10)); }
          if (e.key === "ArrowRight") { e.preventDefault(); const n = cur + 10; setReplay(n >= end - 8 ? null : n); }
          if (e.key === "Escape" || e.key === "End") setReplay(null);
        }}>
        {LANES.map((l, i) => {
          const y = 6 + i * laneH + laneH / 2;
          return <g key={l}><text x={0} y={y + 4} fontSize="11" fill="var(--bone-3)" className="num">{l}</text><line x1={LEFT} x2={W - 8} y1={y} y2={y} stroke="var(--line-strong)" /></g>;
        })}
        {events.filter((e) => e.ts >= start).map((e) => {
          const i = LANES.indexOf(e.layer); if (i < 0) return null;
          const y = 6 + i * laneH + laneH / 2;
          const hot = isHot(e);
          return <rect key={e.event_id} x={x(e.ts) - 1.5} y={y - (hot ? 8 : 5)} width={3} height={hot ? 16 : 10} fill={hot ? "var(--signal)" : "var(--bone-2)"} opacity={replayTs !== null && e.ts > replayTs ? 0.25 : 1} />;
        })}
        <line x1={x(replayTs ?? end)} x2={x(replayTs ?? end)} y1={0} y2={H - 14} stroke={replayTs === null ? "var(--bone-3)" : "var(--signal)"} strokeWidth={replayTs === null ? 1 : 2} strokeDasharray={replayTs === null ? "3 3" : undefined} />
        <text x={W - 8} y={H - 2} textAnchor="end" fontSize="11" fill="var(--bone-3)" className="num">now</text>
        <text x={LEFT} y={H - 2} fontSize="11" fill="var(--bone-3)" className="num">-10 min</text>
      </svg>
    </div>
  );
}
