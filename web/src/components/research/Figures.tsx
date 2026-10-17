"use client";
import { useMemo, useRef, useState } from "react";
import { useGsap } from "@/hooks/useGsap";
import { motion, prefersReducedMotion } from "@/lib/animations/core";
import { onEnter } from "@/lib/animations/scroll";
import { ease } from "@/lib/animations/tokens";
import { fact } from "@/lib/content/facts";
import clsx from "clsx";

const Frame = ({ children, caption }: { children: React.ReactNode; caption: string }) => (
  <figure className="surface-1 p-6 md:p-8">{children}<figcaption className="mt-4 text-xs text-bone-3">{caption}</figcaption></figure>
);

/** 1. Fusion is blind to a sub-threshold attacker */
export function BlindFig() {
  const [s, setS] = useState(0.8);
  const pts = useMemo(() => Array.from({ length: 5 }, (_, li) => Array.from({ length: 6 }, (_, j) => 0.9 + ((li * 7 + j * 3) % 10) / 100)), []);
  const crossed = pts.flat().filter((j) => s * j > 1).length;
  const ROW = 34;
  return (
    <Frame caption="Schematic. Each dot is one slice of a split attack; each line is one layer's threshold.">
      <svg viewBox={`0 0 320 ${ROW * 5 + 12}`} className="w-full" role="img" aria-label={`Five layers with thresholds. ${crossed} of 30 attack slices cross a threshold at this signal level.`}>
        {pts.map((row, i) => {
          const y = 12 + i * ROW;
          return (
            <g key={i}>
              <text x={0} y={y + 4} fontSize="10" fill="var(--bone-3)" className="num">L{i + 1}</text>
              <line x1={26} x2={316} y1={y} y2={y} stroke="var(--bone)" strokeOpacity=".45" />
              {row.map((j, k) => { const lvl = s * j; return <rect key={k} x={36 + k * 46} y={y + 22 - lvl * 22 - 3} width={6} height={6} fill={lvl > 1 ? "var(--signal)" : "var(--bone-2)"} />; })}
            </g>
          );
        })}
      </svg>
      <label htmlFor="sig" className="mt-4 block text-sm text-bone-2">Attack signal per slice</label>
      <input id="sig" type="range" min={0.6} max={1.3} step={0.01} value={s} onChange={(e) => setS(Number(e.target.value))} className="h-11 w-full cursor-pointer accent-[var(--signal)]" />
      <p className="num mt-1 text-2xl" role="status">{crossed === 0 ? "0 detections" : `${crossed} slices cross a threshold`}</p>
      <p className="mt-1 text-sm text-bone-2">On the real benchmark: {fact("research.blind").display} detections across 510 certified sessions.</p>
    </Frame>
  );
}

/** 2 and 5 reuse the overlap picture */
export function OverlapFig() {
  const root = useRef<HTMLDivElement>(null);
  useGsap(root, () => {
    const el = root.current; if (!el || prefersReducedMotion()) return;
    const c2 = el.querySelector("[data-c2]"); if (!c2) return;
    motion.set(c2, { x: 90 });
    return onEnter(el, () => motion.to(c2, { x: 0, duration: 1.6, ease: ease.inOut }), "top 75%");
  }, []);
  return (
    <div ref={root}>
      <Frame caption="Two detection sets. The learned fusion rule and the best single layer flag exactly the same sessions.">
        <svg viewBox="0 0 260 120" className="w-full" role="img" aria-label="Two detection sets that overlap completely.">
          <circle cx="100" cy="60" r="46" fill="none" stroke="var(--bone-2)" strokeWidth="2.5" />
          <circle data-c2 cx="100" cy="60" r="46" fill="none" stroke="var(--signal)" strokeWidth="2.5" />
          <text x="170" y="56" fontSize="11" fill="var(--bone-3)" className="num">Jaccard</text>
          <text x="170" y="80" fontSize="24" fill="var(--bone)" className="num">{fact("research.jaccard").display}</text>
        </svg>
      </Frame>
    </div>
  );
}

/** 3. Valid fusion ranks well but cannot operate inside the budget */
export function BudgetFig() {
  return (
    <Frame caption="A learned alarm ranks attacks well, but cannot be operated inside a 2% false-alarm budget.">
      <p className="text-sm text-bone-2">Ranks attacks apart (AUROC)</p>
      <div className="mt-2 h-4 bg-ink-3"><div className="h-full bg-bone" style={{ width: "97.4%" }} /></div>
      <p className="num mt-1 text-2xl">0.974</p>
      <p className="mt-6 text-sm text-bone-2">Usable at a 2% false-alarm budget</p>
      <div className="mt-2 h-4 border border-signal" aria-hidden />
      <p className="num mt-1 text-2xl text-signal">cannot operate</p>
    </Frame>
  );
}

/** 4. Pipelines destroy evidence at their interfaces */
export function BitFig() {
  const [bit, setBit] = useState(false);
  const bars = useMemo(() => Array.from({ length: 20 }, (_, i) => 0.18 + ((i * 37) % 70) / 100), []);
  return (
    <Frame caption="A guard that returns only safe or unsafe turns a ranking into a single bit.">
      <div className="flex h-36 items-end gap-1.5" role="img" aria-label={bit ? "All scores collapsed to two levels." : "Twenty scores with a full ranking."}>
        {bars.map((b, i) => <span key={i} className="flex-1 transition-[height,background-color] duration-700 ease-out" style={{ height: `${(bit ? (b > 0.55 ? 0.9 : 0.25) : b) * 100}%`, background: bit && b > 0.55 ? "var(--signal)" : "var(--bone-2)" }} />)}
      </div>
      <div className="mt-5 flex items-center justify-between gap-4">
        <button onClick={() => setBit((v) => !v)} className="h-11 rounded-full border border-line-strong px-5 text-sm hover:bg-ink-3">{bit ? "Show the ranking" : "Pass through the interface"}</button>
        <p className="num text-2xl" role="status">AUROC {bit ? "0.500" : "0.714"}</p>
      </div>
    </Frame>
  );
}

/** 5. It is not just our system */
export function StackFig() {
  const [mode, setMode] = useState<"deployed" | "indep">("deployed");
  const n = mode === "deployed" ? 0 : 10;
  return (
    <Frame caption="107 certified sub-threshold sessions against LLM Guard plus Llama Guard 3. Each square is one session.">
      <div className="grid grid-cols-[repeat(18,minmax(0,1fr))] gap-1" role="img" aria-label={`${n} of 107 sessions caught`}>
        {Array.from({ length: 107 }).map((_, i) => <span key={i} className="aspect-square transition-colors duration-500" style={{ background: i < n ? "var(--signal)" : "var(--ink-3)" }} />)}
      </div>
      <div className="mt-5 flex flex-wrap gap-2" role="group" aria-label="Fusion rule">
        {([["deployed", "Deployed rule"], ["indep", "Assumes independence"]] as const).map(([k, l]) => (
          <button key={k} aria-pressed={mode === k} onClick={() => setMode(k)} className={clsx("h-11 rounded-full border px-5 text-sm", mode === k ? "border-signal text-bone" : "border-line text-bone-2 hover:bg-ink-2")}>{l}</button>
        ))}
      </div>
      <p className="num mt-3 text-2xl" role="status">{n} of 107 caught</p>
    </Frame>
  );
}

/** 6. More layers can mean more places to hide */
export function HeadroomFig() {
  const lo = fact("research.capacity.low"), hi = fact("research.capacity.high"), s2 = fact("research.capacity.stack2");
  const root = useRef<HTMLDivElement>(null);
  useGsap(root, () => {
    const el = root.current; if (!el || prefersReducedMotion()) return;
    const bars = el.querySelectorAll("[data-fill]");
    motion.set(bars, { scaleX: 0, transformOrigin: "0 50%" });
    return onEnter(el, () => motion.to(bars, { scaleX: 1, duration: 1.2, stagger: 0.2, ease: ease.out }), "top 75%");
  }, []);
  return (
    <div ref={root}>
      <Frame caption="Share of attack headroom no layer defends against a distributed attacker.">
        <p className="text-sm text-bone-2">DIDA</p>
        <div className="relative mt-2 h-6 bg-ink-3" role="img" aria-label={`${lo.display} to ${hi.display} undefended`}>
          <div data-fill className="absolute inset-y-0 bg-bone-3" style={{ left: 0, width: `${lo.value}%` }} />
          <div data-fill className="absolute inset-y-0 bg-signal" style={{ left: `${lo.value}%`, width: `${hi.value - lo.value}%` }} />
        </div>
        <p className="num mt-1 text-2xl">{lo.display} to {hi.display}</p>
        <p className="mt-6 text-sm text-bone-2">Third-party stack</p>
        <div className="mt-2 h-6 bg-ink-3"><div data-fill className="h-full bg-bone-3" style={{ width: `${s2.value}%` }} /></div>
        <p className="num mt-1 text-2xl">{s2.display}</p>
      </Frame>
    </div>
  );
}
