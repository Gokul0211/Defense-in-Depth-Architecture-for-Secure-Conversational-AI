"use client";
import { useEffect, useRef } from "react";
import type { ThreatEvent } from "@/lib/api/types";
import { GAP, OPENINGS, STROKE, WALLS, dPoint, wallRadius } from "@/lib/three/labyrinth-geometry";
import { RING, hash01, isHot } from "@/lib/console-utils";
import { prefersReducedMotion } from "@/lib/animations/core";

const DECAY = 20;       // seconds an arc stays visible
const WAVE = 1.4;       // seconds a shockwave runs
const SPAN = 0.07;      // fraction of a ring an event arc covers

export interface RadarProps {
  /** newest first */
  events: ThreatEvent[];
  /** seconds; live passes Date.now()/1000, replay passes the scrub time */
  clock: () => number;
  /** disconnected: rings only, nothing animates */
  frozen?: boolean;
  className?: string;
}

/**
 * The labyrinth as a radar. Five D-shaped rings; every real event draws an arc on the ring of the layer
 * that reported it, at an angle derived from its session. Blocked events send a shockwave outward.
 * Rendering is a pure function of (events, clock), so scrubbing the timeline replays exactly.
 */
export function Radar({ events, clock, frozen, className = "" }: RadarProps) {
  const box = useRef<HTMLDivElement>(null);
  const cv = useRef<HTMLCanvasElement>(null);
  const ev = useRef(events); ev.current = events;
  const clk = useRef(clock); clk.current = clock;
  const frz = useRef(frozen); frz.current = frozen;

  useEffect(() => {
    const canvas = cv.current, el = box.current;
    if (!canvas || !el) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const reduced = prefersReducedMotion();
    let w = 0, h = 0, dpr = 1, raf = 0, running = true, visible = true;

    const resize = () => {
      dpr = Math.min(2, window.devicePixelRatio || 1);
      w = el.clientWidth; h = el.clientHeight;
      canvas.width = Math.round(w * dpr); canvas.height = Math.round(h * dpr);
      canvas.style.width = `${w}px`; canvas.style.height = `${h}px`;
      if (!running || frz.current || reduced) draw(0);
    };

    const ringPts = (k: number, scale: number, cx: number, cy: number, sc: number, f0 = 0, f1 = 1, n = 90): [number, number][] => {
      const r = wallRadius(k) * scale, out: [number, number][] = [];
      for (let i = 0; i <= n; i++) { const [x, y] = dPoint(r, f0 + (f1 - f0) * (i / n)); out.push([cx + x * sc, cy - y * sc]); }
      return out;
    };

    const stroke = (pts: [number, number][], color: string, width: number, alpha: number) => {
      ctx.beginPath();
      pts.forEach(([x, y], i) => (i ? ctx.lineTo(x, y) : ctx.moveTo(x, y)));
      ctx.globalAlpha = alpha; ctx.strokeStyle = color; ctx.lineWidth = width; ctx.lineJoin = "round"; ctx.stroke(); ctx.globalAlpha = 1;
    };

    function draw(t: number) {
      ctx!.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx!.clearRect(0, 0, w, h);
      if (w < 60 || h < 60) return;   // not laid out yet
      const sc = (Math.min(w, h) * 0.5 - 24) / (wallRadius(0) + STROKE);
      const cx = w / 2, cy = h / 2;
      const dead = !!frz.current;

      // rings, each with its single opening
      for (let k = 0; k < WALLS; k++) {
        const per = wallRadius(k) * (4 + Math.PI);
        const gf = (GAP / 2) / per, o = OPENINGS[k];
        const pts = ringPts(k, 1, cx, cy, sc, o + gf, o + 1 - gf, 120);
        stroke(pts, "#efebe3", Math.max(2, STROKE * sc * 0.55), dead ? 0.1 : 0.2);
        // label
        const [lx, ly] = dPoint(wallRadius(k), 0.0);
        ctx!.fillStyle = dead ? "rgba(111,108,102,.7)" : "#a9a59d"; ctx!.font = `500 ${Math.max(10, 11)}px var(--font-geist-mono), monospace`;
        ctx!.textAlign = "right"; ctx!.fillText(`L${k + 1}`, cx + lx * sc - 10, cy - ly * sc + 4);
      }
      // core
      const coreS = 12 * sc * (dead ? 0.8 : 1);
      ctx!.fillStyle = dead ? "#6f6c66" : "#ff4f1f"; ctx!.fillRect(cx - coreS / 2, cy - coreS / 2, coreS, coreS);
      if (dead) return;

      // idle sweep: a faint highlight walking each ring, slowest on the outside
      if (!reduced) {
        for (let k = 0; k < WALLS; k++) {
          const f = (t * (0.025 + k * 0.012)) % 1;
          stroke(ringPts(k, 1, cx, cy, sc, f, f + 0.05, 14), "#efebe3", Math.max(2, STROKE * sc * 0.55), 0.16);
        }
      }

      // events: pure function of (events, now)
      const now = clk.current();
      const list = ev.current;
      let drawn = 0;
      for (let i = 0; i < list.length && drawn < 400; i++) {
        const e = list[i];
        const age = now - e.ts;
        if (age < 0) continue;            // replay: this event has not happened yet
        if (age > DECAY) break;           // newest first, so everything after is older
        drawn++;
        const a = Math.pow(1 - age / DECAY, 1.4);
        const hot = isHot(e);
        const color = hot ? "#ff4f1f" : "#efebe3";
        if (e.layer === "TIB") {
          ctx!.beginPath(); ctx!.arc(cx, cy, Math.max(1, coreS * (0.9 + age * 0.9)), 0, Math.PI * 2);
          ctx!.globalAlpha = a * 0.7; ctx!.strokeStyle = "#ff4f1f"; ctx!.lineWidth = 2; ctx!.stroke(); ctx!.globalAlpha = 1;
          continue;
        }
        const k = RING[e.layer]; if (k === undefined) continue;
        const f = hash01(e.session_id) + hash01(e.event_id) * 0.04;
        const width = Math.max(4, STROKE * sc * (hot ? 1 : 0.7));
        stroke(ringPts(k, 1, cx, cy, sc, f - SPAN / 2, f + SPAN / 2, 12), color, width, a);
        if ((e.action === "BLOCKED" || e.severity === "CRITICAL") && age < WAVE) {
          const p = age / WAVE;
          stroke(ringPts(k, 1 + p * 0.28, cx, cy, sc, 0, 1, 100), "#ff4f1f", 2, (1 - p) * 0.55);
        }
      }
    }

    const loop = (ms: number) => {
      raf = requestAnimationFrame(loop);
      if (!visible || document.hidden || frz.current) return;
      draw(ms / 1000);
    };

    resize();
    const ro = new ResizeObserver(resize); ro.observe(el);
    const io = new IntersectionObserver(([e]) => { visible = e.isIntersecting; }, { threshold: 0 }); io.observe(el);
    if (!reduced) raf = requestAnimationFrame(loop);
    // reduced motion: redraw about once a second so arcs still age without continuous animation
    const slow = reduced ? setInterval(() => draw(0), 1000) : undefined;
    const redraw = setInterval(() => { if (frz.current) draw(0); }, 800);
    return () => { running = false; cancelAnimationFrame(raf); ro.disconnect(); io.disconnect(); clearInterval(redraw); if (slow) clearInterval(slow); };
  }, []);

  return (
    <div ref={box} className={className || "relative size-full"}>
      <canvas ref={cv} aria-hidden="true" className="absolute inset-0" />
    </div>
  );
}
