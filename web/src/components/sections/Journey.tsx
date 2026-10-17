"use client";
import { useEffect, useMemo, useRef } from "react";
import { WALL_PATHS } from "@/components/brand/LabyrinthMark";
import { SourceNote } from "@/components/ui/SourceNote";
import { LAYERS } from "@/lib/content/layers";
import { buildTrace } from "@/lib/three/labyrinth-geometry";
import { motion, ScrollTrigger, prefersReducedMotion } from "@/lib/animations/core";

const TRACE = buildTrace();
const ATTACK_STOP_WALL = 3; // the attack dies at L4, the tool-call check
const CAPTIONS = ["L1  input scan", "L2  document scan", "L3  conversation scan", "L4  tool-call check", "L5  output scan", "evidence bus"];

const clamp = (v: number, a = 0, b = 1) => Math.min(b, Math.max(a, v));

/** The Packet: a normal request and an attack walk the maze together; scroll moves them. */
export function Journey() {
  const root = useRef<HTMLElement>(null);
  const guide = useRef<SVGPathElement>(null);
  const prog = useRef<SVGPathElement>(null);
  const benign = useRef<SVGRectElement>(null);
  const attack = useRef<SVGRectElement>(null);
  const flare = useRef<SVGCircleElement>(null);
  const core = useRef<SVGRectElement>(null);
  const walls = useRef<(SVGPathElement | null)[]>([]);
  const caption = useRef<HTMLParagraphElement>(null);
  const verdictB = useRef<HTMLSpanElement>(null);
  const verdictA = useRef<HTMLSpanElement>(null);
  const panels = useRef<(HTMLLIElement | null)[]>([]);
  const state = useRef({ seg: -1 });
  const W = useMemo(() => [0, ...TRACE.marks, 1], []);

  useEffect(() => {
    const g = guide.current, pr = prog.current, b = benign.current, a = attack.current, fl = flare.current, co = core.current;
    const list = root.current?.querySelector("ol");
    if (!g || !pr || !b || !a || !fl || !co || !list) return;
    const len = g.getTotalLength();
    const reduced = prefersReducedMotion();
    pr.style.strokeDasharray = `${len}`;

    const place = (el: SVGRectElement, frac: number, size: number) => {
      const pt = g.getPointAtLength(len * clamp(frac));
      el.setAttribute("x", String(pt.x - size / 2)); el.setAttribute("y", String(pt.y - size / 2));
      return pt;
    };

    const render = (s: number) => {
      const segCount = W.length - 1;
      const seg = Math.min(segCount - 1, Math.floor(s * segCount));
      const local = clamp(s * segCount - seg);
      const pb = W[seg] + (W[seg + 1] - W[seg]) * local;   // benign path fraction
      const stopAt = TRACE.marks[ATTACK_STOP_WALL] - 0.012;
      const pa = Math.min(pb + 0.02, stopAt);              // the attack leads, then stops at L4
      place(b, pb, 4.6);
      const pt = place(a, pa, 5.6);
      pr.style.strokeDashoffset = String(len * (1 - pb));
      const stopped = pb + 0.02 >= stopAt;
      fl.setAttribute("cx", String(pt.x)); fl.setAttribute("cy", String(pt.y));
      fl.style.opacity = stopped ? "1" : "0";
      a.style.opacity = "1";
      a.setAttribute("fill", "var(--signal)");
      co.style.opacity = String(seg === 5 ? 0.45 + 0.55 * local : 1);
      co.setAttribute("transform", seg === 5 ? `translate(100 100) scale(${1 + local * 0.9}) translate(-100 -100)` : "");

      walls.current.forEach((w, k) => {
        if (!w) return;
        const scanning = k === seg && seg < 5;
        w.style.stroke = scanning ? "var(--signal)" : "var(--bone)";
        w.style.opacity = scanning ? "1" : k < seg || seg === 5 ? "0.9" : "0.32";
      });

      if (verdictB.current) verdictB.current.textContent = seg < 5 ? (local > 0.85 ? "passed" : "scanning") : "reached the core";
      if (verdictA.current) verdictA.current.textContent = stopped ? "blocked at L4" : seg === 0 ? "entering" : "in flight";
      if (verdictA.current) verdictA.current.style.color = stopped ? "var(--signal)" : "var(--bone-2)";

      if (seg !== state.current.seg) {
        state.current.seg = seg;
        const el = caption.current;
        if (el) {
          if (reduced) el.textContent = CAPTIONS[seg];
          else motion.to(el, { duration: 0.7, scrambleText: { text: CAPTIONS[seg], chars: "01#/<>_", speed: 0.6 }, overwrite: true });
        }
        panels.current.forEach((p, i) => { if (p) { p.style.opacity = i === seg ? "1" : "0.28"; } });
      }
    };

    render(0);
    const st = ScrollTrigger.create({ trigger: list, start: "top 55%", end: "bottom 55%", onUpdate: (self) => render(self.progress) });
    return () => st.kill();
  }, [W]);

  return (
    <section id="layers" ref={root} aria-labelledby="journey-title" className="relative">
      <div className="container-x pt-28 md:pt-40">
        <h2 id="journey-title" className="display max-w-[16ch]">Follow one request in</h2>
        <p className="mt-6 max-w-[40ch] text-xl text-bone-2">A normal request and an attack set off together. Scroll to follow them through the five walls.</p>
        <p className="mt-6 flex flex-wrap gap-x-6 gap-y-2 text-sm text-bone-2">
          <span className="inline-flex items-center gap-2"><svg width="10" height="10" aria-hidden><rect width="10" height="10" fill="var(--bone)" /></svg>Your request</span>
          <span className="inline-flex items-center gap-2"><svg width="10" height="10" aria-hidden><rect width="10" height="10" fill="var(--signal)" /></svg>The attack</span>
        </p>
      </div>
      <div className="container-x grid md:grid-cols-[1.05fr_1fr] md:gap-12">
        <div className="sticky top-0 z-20 -mx-5 flex h-[46vh] flex-col justify-center border-b border-line bg-ink-0 px-5 md:mx-0 md:h-dvh md:border-0 md:bg-transparent md:px-0">
          <svg viewBox="0 0 200 200" role="img" aria-label="Animated map: a normal request and an attack travel inward through five walls. The request reaches the core. The attack is stopped at the fourth wall." className="mx-auto max-h-[34vh] w-full md:max-h-[72vh]">
            <g fill="none" strokeWidth={9} strokeLinejoin="miter">
              {WALL_PATHS.map((w, i) => (
                <path key={i} ref={(el) => { walls.current[i] = el; }} d={w.d} pathLength={100} strokeDasharray={w.dash} strokeDashoffset={w.off} stroke="var(--bone)" style={{ opacity: 0.32, transition: "opacity .3s, stroke .3s" }} />
              ))}
            </g>
            <path ref={guide} d={TRACE.d} fill="none" stroke="var(--bone-3)" strokeWidth={1} strokeDasharray="1.5 3" opacity={0.7} />
            <path ref={prog} d={TRACE.d} fill="none" stroke="var(--bone)" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round" strokeDashoffset={9999} />
            <rect ref={core} x={94} y={94} width={12} height={12} fill="var(--signal)" />
            <circle ref={flare} r={7} fill="none" stroke="var(--signal)" strokeWidth={1.4} style={{ opacity: 0, transition: "opacity .25s" }}>
              <animate attributeName="r" values="5;11;5" dur="1.4s" repeatCount="indefinite" />
            </circle>
            <rect ref={attack} width={5.6} height={5.6} fill="var(--signal)" />
            <rect ref={benign} width={4.6} height={4.6} fill="var(--bone)" />
          </svg>
          <div className="num mx-auto mt-3 w-full max-w-md text-sm">
            <p ref={caption} aria-live="off" className="text-signal">{CAPTIONS[0]}</p>
            <p className="mt-1 text-bone-2">request: <span ref={verdictB} className="text-bone">scanning</span> · attack: <span ref={verdictA} className="text-bone-2">entering</span></p>
          </div>
        </div>
        <ol className="relative z-10 pb-[18vh]">
          {LAYERS.map((l, i) => (
            <li key={l.id} ref={(el) => { panels.current[i] = el; }} className="flex min-h-[78vh] flex-col justify-center py-10 transition-opacity duration-300 md:min-h-screen" style={{ opacity: i === 0 ? 1 : 0.28 }}>
              <p className="num text-base text-signal">{l.id}</p>
              <h3 className="mt-3 text-4xl font-semibold tracking-tight md:text-5xl">{l.name}</h3>
              <p className="mt-3 text-xl text-bone-2">{l.stops}</p>
              <p className="mt-6 max-w-[44ch] text-lg leading-relaxed text-bone">{l.blurb}</p>
              <p className="mt-10">
                <span className="num text-6xl font-medium tracking-tight">{l.metric.value}</span><SourceNote source={l.metric.source} />
                <span className="mt-2 block text-base text-bone-2">{l.metric.label}</span>
              </p>
            </li>
          ))}
        </ol>
      </div>
    </section>
  );
}
