"use client";
import { useRef, useState, type ReactNode } from "react";
import { SpotlightCard } from "@/components/animation/SpotlightCard";
import { TiltCard } from "@/components/animation/TiltCard";
import { ScrollReveal } from "@/components/animation/ScrollReveal";
import { SourceNote } from "@/components/ui/SourceNote";
import { useGsap } from "@/hooks/useGsap";
import { motion, prefersReducedMotion } from "@/lib/animations/core";
import { onEnter } from "@/lib/animations/scroll";
import { ease } from "@/lib/animations/tokens";
import { CONTRIBUTIONS, type Contribution } from "@/lib/content/contributions";
import clsx from "clsx";

function Cell({ c, span, tint, tilt, children, note }: { c: Contribution; span: string; tint: string; tilt?: boolean; children: ReactNode; note: string }) {
  const inner = (
    <SpotlightCard tabIndex={0} className={clsx("flex h-full flex-col rounded-[var(--radius-panel)] p-6", tint)}>
      <div className="flex items-baseline gap-3"><span className="num text-sm text-signal">{c.id}</span><h3 className="text-lg font-semibold tracking-tight">{c.name}</h3></div>
      <p className="mt-2 max-w-[48ch] text-sm text-bone-2">{c.truth}</p>
      <div className="my-5 flex-1">{children}</div>
      <p className="text-sm text-bone">{c.weight}<SourceNote source={note} /></p>
    </SpotlightCard>
  );
  return <div className={clsx("min-w-0", span)}>{tilt ? <TiltCard className="h-full">{inner}</TiltCard> : inner}</div>;
}

const TH = [20, 40, 60, 80, 100];

function BoundViz() {
  const [cut, setCut] = useState(false);
  return (
    <div onPointerEnter={() => setCut(true)} onPointerLeave={() => setCut(false)} onFocus={() => setCut(true)} onBlur={() => setCut(false)}>
      <svg viewBox="0 0 300 120" className="w-full" role="img" aria-label="Five threshold lines. Attack points sit just under every threshold, so nothing crosses one until the cut point moves below a threshold.">
        {TH.map((y, i) => <g key={i}><line x1="10" x2="290" y1={y} y2={y} stroke="var(--line-strong)" /><text x="292" y={y + 3} fontSize="8" fill="var(--bone-3)" textAnchor="end" className="num">L{i + 1}</text></g>)}
        {[0, 1, 2, 3, 4].map((i) => Array.from({ length: 6 }).map((_, j) => (
          <rect key={`${i}-${j}`} x={30 + j * 38 + (i % 2) * 8} y={TH[i] + 5 + (j % 3) * 3} width="5" height="5" fill="var(--bone-2)" />
        )))}
        {cut && <rect x="30" y="12" width="5" height="5" fill="var(--signal)" />}
      </svg>
      <p className="num mt-2 text-sm">{cut ? "1 detection: a point crossed one threshold" : "0 detections on 510 certified attacks"}</p>
    </div>
  );
}

function StampViz() {
  return (
    <div className="flex items-center gap-5">
      <div data-stamp className="surface-2 num relative w-40 shrink-0 p-3 text-[0.7rem] leading-relaxed text-bone-2">
        <p>every layer under threshold</p><p>at least k layers carry signal</p>
        <p className="mt-2 inline-block border border-signal px-1.5 py-0.5 text-signal">CERTIFIED</p>
      </div>
      <dl className="num text-sm"><dt className="sr-only-text">Sessions</dt>
        <dd>680 v1</dd><dd>510 v2</dd><dd>447 SPLIT-S2</dd></dl>
    </div>
  );
}

function CapacityViz() {
  return (
    <svg viewBox="0 0 300 70" className="w-full" role="img" aria-label="A budget of 3.002 fits under every threshold. A budget of 3.040 does not.">
      <rect x="0" y="8" width="180" height="14" fill="var(--bone-2)" /><text x="190" y="19" fontSize="10" fill="var(--bone)" className="num">3.002 fits</text>
      <rect x="0" y="40" width="183" height="14" fill="var(--signal)" /><text x="193" y="51" fontSize="10" fill="var(--signal)" className="num">3.040 refused</text>
      <line x1="180" x2="180" y1="2" y2="62" stroke="var(--bone)" strokeDasharray="3 3" />
    </svg>
  );
}

function JaccardViz() {
  return (
    <div>
      <svg viewBox="0 0 220 80" className="w-full max-w-64" role="img" aria-label="Two detection sets that overlap completely, Jaccard 1.0000.">
        <circle data-c1 cx="70" cy="40" r="30" fill="none" stroke="var(--bone-2)" strokeWidth="2" />
        <circle data-c2 cx="70" cy="40" r="30" fill="none" stroke="var(--signal)" strokeWidth="2" />
      </svg>
      <p className="num text-sm">Jaccard 1.0000</p>
    </div>
  );
}

function TaintViz() {
  const n = [[20, 40, 0], [70, 15, 0.2], [70, 65, 0.2], [125, 40, 0.5], [180, 20, 0.7], [180, 60, 0.7], [235, 40, 1]];
  const e = [[0, 1], [0, 2], [1, 3], [2, 3], [3, 4], [3, 5], [4, 6], [5, 6]];
  return (
    <svg viewBox="0 0 255 80" className="w-full" role="img" aria-label="A seven-node provenance graph where distrust accumulates toward a tool call.">
      {e.map(([a, b], i) => <line key={i} x1={n[a][0]} y1={n[a][1]} x2={n[b][0]} y2={n[b][1]} stroke="var(--line-strong)" />)}
      {n.map(([x, y, t], i) => <rect key={i} x={x - 6} y={y - 6} width="12" height="12" fill="var(--signal)" fillOpacity={0.15 + t * 0.85} />)}
    </svg>
  );
}

function TriageViz() {
  return (
    <svg viewBox="0 0 255 40" className="w-full" role="img" aria-label="Five layer ticks. The decision stops at about 3.4 of 5.">
      {[0, 1, 2, 3, 4].map((i) => <line key={i} x1={20 + i * 50} x2={20 + i * 50} y1="10" y2="30" stroke="var(--bone-2)" />)}
      <line x1="20" x2={20 + 2.4 * 50} y1="20" y2="20" stroke="var(--signal)" strokeWidth="2" />
      <rect x={20 + 2.4 * 50 - 2} y="12" width="4" height="16" fill="var(--signal)" />
    </svg>
  );
}

function MiningViz() {
  return (
    <div className="num flex items-center gap-2 text-xs text-bone-2">
      {["L1", "L2", "L4"].map((t) => <span key={t} className="bg-ink-3 px-2 py-1 line-through decoration-bone-3">{t}</span>)}
      <span aria-hidden>to</span><span className="bg-signal-dim px-2 py-1 text-signal">L3</span>
    </div>
  );
}

function ConformalViz() {
  // axis 0 to 16%, so both bars and labels stay inside the card
  const x = (pct: number) => (pct / 16) * 150;
  return (
    <svg viewBox="0 0 255 60" className="w-full" role="img" aria-label="A 1% false-positive target and the 14.8% observed under shift.">
      <rect x="0" y="6" width={x(1)} height="14" fill="var(--bone-2)" /><text x={x(1) + 8} y="17" fontSize="10" fill="var(--bone)" className="num">1% target</text>
      <rect x="0" y="34" width={x(14.8)} height="14" fill="var(--signal)" /><text x={x(14.8) + 8} y="45" fontSize="10" fill="var(--signal)" className="num">14.8% under shift</text>
    </svg>
  );
}

export function KitBento() {
  const root = useRef<HTMLElement>(null);
  useGsap(root, () => {
    const el = root.current; if (!el || prefersReducedMotion()) return;
    const stamp = el.querySelector("[data-stamp]"), c1 = el.querySelector("[data-c1]"), c2 = el.querySelector("[data-c2]");
    const offs: Array<() => void> = [];
    if (stamp) { motion.set(stamp, { opacity: 0, scale: 1.25, rotate: -3 }); offs.push(onEnter(stamp, () => motion.to(stamp, { opacity: 1, scale: 1, rotate: 0, duration: 0.5, ease: "back.out(2.2)" }), "top 85%")); }
    if (c1 && c2) { motion.set(c2, { x: 80 }); offs.push(onEnter(c2, () => motion.to(c2, { x: 0, duration: 1.1, ease: ease.inOut }), "top 85%")); }
    return () => offs.forEach((o) => o());
  }, []);
  const C = CONTRIBUTIONS;
  return (
    <section ref={root} aria-labelledby="kit-title" className="relative py-28 md:py-36">
      <div className="container-x">
        <ScrollReveal><p className="mb-4 text-sm text-signal">Research</p>
        <h2 id="kit-title" className="h2 max-w-[22ch]">The kit, and where each mechanism stops</h2>
        <p className="measure mt-5 text-bone-2">Four pieces prove what a stack of detectors can and cannot catch. Four mechanisms show where each trick runs out.</p></ScrollReveal>
        <ScrollReveal stagger className="mt-14 grid gap-3 md:grid-cols-2 lg:grid-cols-12">
          <Cell c={C.E} span="lg:col-span-7 lg:row-span-2" tint="bg-ink-2" tilt note="README, Contribution E"><BoundViz /></Cell>
          <Cell c={C.G} span="lg:col-span-5" tint="bg-ink-1" tilt note="README, Contribution G"><StampViz /></Cell>
          <Cell c={C.H} span="lg:col-span-5" tint="bg-ink-1" tilt note="README, Contribution H"><CapacityViz /></Cell>
          <Cell c={C.F} span="lg:col-span-6" tint="bg-ink-1" note="README, Contribution F"><JaccardViz /></Cell>
          <Cell c={C.A} span="lg:col-span-3" tint="bg-ink-2" note="README, Contribution A"><TaintViz /></Cell>
          <Cell c={C.B} span="lg:col-span-3" tint="bg-ink-1" note="README, Contribution B"><TriageViz /></Cell>
          <Cell c={C.C} span="lg:col-span-6" tint="bg-ink-2" note="README, Contribution C"><MiningViz /></Cell>
          <Cell c={C.D} span="lg:col-span-6" tint="bg-ink-1" note="README, Contribution D"><ConformalViz /></Cell>
        </ScrollReveal>
      </div>
    </section>
  );
}
