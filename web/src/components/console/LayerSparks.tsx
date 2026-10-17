"use client";
import { useEffect, useMemo, useState } from "react";
import { useConsole } from "@/lib/state/console-store";
import { LAYER_NAMES, isHot } from "@/lib/console-utils";

const LAYERS = ["L1", "L2", "L3", "L4", "L5", "TIB"];
const BUCKETS = 20, BUCKET_S = 30;   // 10 minutes in 30 s buckets

/** One tile per layer: events in the last 10 minutes as a sparkline. Honors the replay position. */
export function LayerSparks() {
  const events = useConsole((s) => s.events);
  const replayTs = useConsole((s) => s.replayTs);
  const [tick, setTick] = useState(() => Date.now() / 1000);
  useEffect(() => { const id = setInterval(() => setTick(Date.now() / 1000), 5000); return () => clearInterval(id); }, []);
  const end = replayTs ?? tick;

  const data = useMemo(() => LAYERS.map((l) => {
    const b = Array(BUCKETS).fill(0) as number[]; let hot = 0, total = 0;
    for (const e of events) {
      if (e.layer !== l || e.ts > end) continue;
      const age = end - e.ts; if (age >= BUCKETS * BUCKET_S) continue;
      b[BUCKETS - 1 - Math.floor(age / BUCKET_S)]++; total++; if (isHot(e)) hot++;
    }
    return { l, b, hot, total };
  }), [events, end]);

  return (
    <div className="grid grid-cols-3 gap-2 sm:grid-cols-6" role="group" aria-label="Events per layer, last 10 minutes">
      {data.map(({ l, b, hot, total }) => {
        const max = Math.max(1, ...b);
        const pts = b.map((v, i) => `${(i / (BUCKETS - 1)) * 100},${28 - (v / max) * 24}`).join(" ");
        return (
          <div key={l} className="surface-1 p-3">
            <div className="flex items-baseline justify-between"><span className="num text-xs text-signal">{l}</span><span className="num text-lg text-bone">{total}</span></div>
            <svg viewBox="0 0 100 30" preserveAspectRatio="none" className="mt-1 h-7 w-full" aria-hidden><polyline points={pts} fill="none" stroke={hot > 0 ? "var(--signal)" : "var(--bone-2)"} strokeWidth="1.6" vectorEffect="non-scaling-stroke" /></svg>
            <p className="mt-1 truncate text-[0.68rem] text-bone-3">{LAYER_NAMES[l]}{hot > 0 && <span className="text-signal"> · {hot} high</span>}</p>
          </div>
        );
      })}
    </div>
  );
}
