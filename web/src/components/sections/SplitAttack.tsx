"use client";
import { useRef, useState } from "react";
import { useGsap } from "@/hooks/useGsap";
import { SourceNote } from "@/components/ui/SourceNote";
import { motion, prefersReducedMotion } from "@/lib/animations/core";
import { onEnter } from "@/lib/animations/scroll";
import { ease } from "@/lib/animations/tokens";
import { fact } from "@/lib/content/facts";

const ACCEPT = fact("research.capacity.accept").value;   // 3.002
const REJECT = fact("research.capacity.reject").value;   // 3.040
const MAX = 3.2;
/** Schematic split of the budget across the five layers. The totals are from the README; the per-layer split is illustrative. */
const SHARE = [0.26, 0.18, 0.22, 0.16, 0.18];
const NAMES = ["L1", "L2", "L3", "L4", "L5"];
const ROW = 60, TOP = 14, LEFT = 38, WIDTH = 330;

export function SplitAttack() {
  const root = useRef<HTMLElement>(null);
  const [budget, setBudget] = useState(2.4);
  const over = budget >= REJECT - 1e-9;
  const fits = budget <= ACCEPT + 1e-9;
  const gap = !fits && !over;

  useGsap(root, () => {
    const el = root.current; if (!el || prefersReducedMotion()) return;
    const blob = el.querySelector<SVGElement>("[data-blob]");
    const shards = el.querySelectorAll<SVGElement>("[data-shard]");
    if (!blob) return;
    motion.set(shards, { opacity: 0, scaleX: 0, transformOrigin: "0 50%" });
    motion.set(blob, { opacity: 1, scale: 1, transformOrigin: "center" });
    return onEnter(el.querySelector("[data-fig]")!, () => {
      const tl = motion.timeline();
      tl.to(blob, { scale: 1.25, duration: 0.5, ease: "power2.out" });
      tl.to(blob, { opacity: 0, scale: 0.6, duration: 0.35 }, 0.5);
      tl.to(shards, { opacity: 1, scaleX: 1, duration: 0.9, stagger: 0.12, ease: ease.out }, 0.55);
      return tl;
    }, "top 70%");
  }, []);

  const scale = WIDTH / MAX;
  return (
    <section ref={root} aria-labelledby="split-title" className="relative py-28 md:py-44">
      <div className="container-x">
        <h2 id="split-title" className="display max-w-[18ch]">The attack nobody sees</h2>
        <p className="mt-6 max-w-[46ch] text-xl text-bone-2">A careful attacker knows every threshold. They split one attack into five pieces and keep each one just under its layer's line. Every wall stays quiet. The core still falls.</p>

        <div className="mt-16 grid items-start gap-12 lg:grid-cols-[1.25fr_1fr]">
          <figure data-fig className="surface-1 p-4 md:p-6">
            <svg viewBox={`0 0 ${LEFT + WIDTH + 24} ${TOP + ROW * 5 + 6}`} className="w-full" role="img" aria-label={`Five layers, each with a threshold. At a budget of ${budget.toFixed(3)} the split attack ${fits ? "stays under every threshold" : gap ? "sits in the gap before the first refused budget" : "crosses the thresholds and is detected"}.`}>
              <circle data-blob cx={LEFT + 14} cy={TOP + ROW * 2.5} r="14" fill="var(--signal)" opacity="0" />
              {NAMES.map((n, i) => {
                const y = TOP + i * ROW + ROW / 2;
                const cap = ACCEPT * SHARE[i];
                const w = Math.max(2, budget * SHARE[i] * scale);
                const crossed = over && budget * SHARE[i] > cap + 1e-9;
                return (
                  <g key={n}>
                    <text x={0} y={y + 4} fontSize="14" fill="var(--bone-2)" className="num">{n}</text>
                    <line x1={LEFT} x2={LEFT + WIDTH} y1={y} y2={y} stroke="var(--line-strong)" strokeDasharray="2 4" />
                    <rect data-shard x={LEFT} y={y - 11} width={w} height={22} fill={crossed ? "var(--signal)" : "var(--bone-2)"} />
                    <line x1={LEFT + cap * scale} x2={LEFT + cap * scale} y1={y - 22} y2={y + 22} stroke={crossed ? "var(--signal)" : "var(--bone)"} strokeWidth="2.5" />
                  </g>
                );
              })}
            </svg>
            <figcaption className="mt-3 text-xs text-bone-3">Schematic. The two budgets are measured values; how the budget divides across layers is illustrative.</figcaption>
          </figure>

          <div>
            <label htmlFor="budget" className="text-sm text-bone-2">Attacker budget</label>
            <p className="num mt-1 text-6xl font-medium tracking-tight">{budget.toFixed(3)}</p>
            <input id="budget" type="range" min={2.4} max={MAX} step={0.002} value={budget} onChange={(e) => setBudget(Number(e.target.value))}
              className="mt-5 h-11 w-full cursor-pointer accent-[var(--signal)]" aria-describedby="budget-help" />
            <p className="num mt-1 text-xs text-bone-3" aria-hidden>fits up to {ACCEPT.toFixed(3)} · first refused {REJECT.toFixed(3)}</p>
            <p id="budget-help" className="sr-only-text">Drag to change the attacker's budget. 3.002 is the largest that fits under every threshold. 3.040 is the first that does not.</p>
            <p role="status" className={`mt-6 text-lg ${over ? "text-signal" : "text-bone"}`}>
              {fits ? "Fits under every threshold. Nothing fires." : gap ? "Between the two measured budgets. Not measured here." : "Does not fit. A layer finally sees it."}
              <SourceNote source="README, Contribution H" />
            </p>
            <div className="mt-10 border-t border-line pt-6">
              <p className="num text-5xl font-medium">{fact("research.blind").display}</p>
              <p className="mt-2 max-w-[34ch] text-bone-2">{fact("research.blind").label}<SourceNote source={fact("research.blind").source} /></p>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
