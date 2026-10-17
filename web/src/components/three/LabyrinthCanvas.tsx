"use client";
import { useEffect, useRef, useState } from "react";
import * as THREE from "three";
import { LabyrinthMark } from "@/components/brand/LabyrinthMark";
import { Stage } from "@/lib/three/stage";
import { buildLabyrinth, type LabyrinthHandle } from "@/lib/three/labyrinth-scene";
import { pickTier, tierConfig, type Tier } from "@/lib/three/quality";
import { motion, prefersReducedMotion } from "@/lib/animations/core";
import { pageState } from "@/lib/state/page-state";
import { LAYERS } from "@/lib/content/layers";

export interface CanvasReady { handle: LabyrinthHandle; stage: Stage; reduced: boolean }

/**
 * The labyrinth scene. The static SVG mark sits underneath at the same position and scale, so there is
 * no layout shift; the WebGL canvas cross-fades over it once the scene is ready.
 */
export default function LabyrinthCanvas({ onReady, forceTier, hoverLayers = true, ambient = true, particleScale = 1, idleSpin = true, className = "", label }: {
  onReady?: (r: CanvasReady) => void; forceTier?: Tier; hoverLayers?: boolean; ambient?: boolean; particleScale?: number; idleSpin?: boolean; className?: string; label: string;
}) {
  const boxRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const tipRef = useRef<HTMLDivElement>(null);
  const [ready, setReady] = useState(false);
  const readyCb = useRef(onReady);
  readyCb.current = onReady;

  useEffect(() => {
    const box = boxRef.current, canvas = canvasRef.current;
    if (!box || !canvas) return;
    const reduced = prefersReducedMotion();
    let stage: Stage | null = null;
    const cleanups: Array<() => void> = [];
    let gone = false;
    try {
      stage = new Stage({ canvas, container: box, tier: forceTier ?? pickTier(), govern: true, staticFrame: reduced, onContextLost: () => setReady(false) });
      const cfg = stage.cfg;
      const handle = buildLabyrinth(stage, { particles: Math.floor(cfg.particles * particleScale), idleSpin: idleSpin && !reduced, ambient, parallaxDeg: 3 });
      if (reduced) {
        handle.state.rise.fill(1); handle.state.core = 1;
        handle.setParticleActivity(0);
      }

      // pointer parallax, eased
      const px = motion.quickTo(handle.state.pointer, "x", { duration: 0.9, ease: "power3.out" });
      const py = motion.quickTo(handle.state.pointer, "y", { duration: 0.9, ease: "power3.out" });
      if (!reduced) {
        const move = (e: PointerEvent) => { px((e.clientX / window.innerWidth) * 2 - 1); py((e.clientY / window.innerHeight) * 2 - 1); };
        window.addEventListener("pointermove", move, { passive: true });
        cleanups.push(() => window.removeEventListener("pointermove", move));
      }

      // CTA hover brightens the core
      cleanups.push(pageState.subscribe((s) => {
        if (reduced) return;
        motion.to(handle.state, { flare: s.ctaHover ? 1 : 0, duration: 0.5, ease: "power2.out", overwrite: "auto" });
        if (s.ctaHover) motion.fromTo(handle.state, { pulse: 0 }, { pulse: 1, duration: 0.5, yoyo: true, repeat: 1, ease: "power2.inOut", overwrite: "auto" });
      }));

      // cursor probe: the cursor's point on the floor lights nearby walls and pushes particles aside
      if (hoverLayers && !reduced) {
        const plane = new THREE.Plane(new THREE.Vector3(0, 1, 0), -0.3), ray = new THREE.Raycaster(), ndc = new THREE.Vector2(), hit = new THREE.Vector3();
        const pxq = motion.quickTo(handle.state.probe, "x", { duration: 0.35, ease: "power3.out" });
        const pzq = motion.quickTo(handle.state.probe, "z", { duration: 0.35, ease: "power3.out" });
        const move = (e: PointerEvent) => {
          const r = canvas.getBoundingClientRect();
          const inside = e.clientX >= r.left && e.clientX <= r.right && e.clientY >= r.top && e.clientY <= r.bottom;
          if (!inside) { motion.to(handle.state.probe, { amt: 0, duration: 0.5, overwrite: "auto" }); return; }
          ndc.set(((e.clientX - r.left) / r.width) * 2 - 1, -((e.clientY - r.top) / r.height) * 2 + 1);
          ray.setFromCamera(ndc, stage!.camera);
          if (ray.ray.intersectPlane(plane, hit)) { pxq(hit.x); pzq(hit.z); motion.to(handle.state.probe, { amt: 1, duration: 0.4, overwrite: "auto" }); }
        };
        window.addEventListener("pointermove", move, { passive: true });
        cleanups.push(() => window.removeEventListener("pointermove", move));
      }

      // raycast hover on the high tier: brighten a wall and name its layer
      if (cfg.raycast && hoverLayers && !reduced) {
        const ray = new THREE.Raycaster(), ndc = new THREE.Vector2();
        let hovered = -1;
        const onMove = (e: PointerEvent) => {
          const r = canvas.getBoundingClientRect();
          ndc.set(((e.clientX - r.left) / r.width) * 2 - 1, -((e.clientY - r.top) / r.height) * 2 + 1);
          ray.setFromCamera(ndc, stage!.camera);
          const hit = ray.intersectObjects(handle.walls, false)[0];
          const k = hit ? handle.walls.indexOf(hit.object as THREE.Mesh) : -1;
          if (k !== hovered) {
            if (hovered >= 0) motion.to(handle.state.highlight, { [hovered]: 0, duration: 0.3, overwrite: "auto" });
            if (k >= 0) motion.to(handle.state.highlight, { [k]: 0.65, duration: 0.3, overwrite: "auto" });
            hovered = k;
          }
          const tip = tipRef.current;
          if (tip) {
            if (k >= 0) { tip.textContent = `${LAYERS[k].id}, ${LAYERS[k].name}`; tip.style.opacity = "1"; tip.style.transform = `translate(${e.clientX - r.left + 14}px, ${e.clientY - r.top + 14}px)`; } else tip.style.opacity = "0";
          }
        };
        const onLeave = () => { if (hovered >= 0) motion.to(handle.state.highlight, { [hovered]: 0, duration: 0.3, overwrite: "auto" }); hovered = -1; if (tipRef.current) tipRef.current.style.opacity = "0"; };
        canvas.addEventListener("pointermove", onMove); canvas.addEventListener("pointerleave", onLeave);
        cleanups.push(() => { canvas.removeEventListener("pointermove", onMove); canvas.removeEventListener("pointerleave", onLeave); });
      }

      // experimental WebGPU compute storm: opt in with ?gpu=1 (see lib/three/webgpu-storm.ts)
      if (hoverLayers && !reduced && "gpu" in navigator && new URLSearchParams(location.search).get("gpu") === "1") {
        import("@/lib/three/webgpu-storm").then(async (m) => {
          try {
            const off = await m.attachStorm({ container: box, state: handle.state });
            if (gone) { off(); return; }
            cleanups.push(off); handle.setParticleActivity(0);
          } catch (e) { console.warn("[dida] WebGPU storm unavailable, keeping the WebGL particles", e); }
        });
      }

      stage.onTierChange = (c) => handle.setParticleActivity(Math.floor(c.particles * particleScale));
      stage.renderOnce();
      setReady(true);
      readyCb.current?.({ handle, stage, reduced });
      if (!reduced) stage.start();
    } catch (err) {
      console.warn("[dida] WebGL unavailable, keeping the static mark", err);
    }
    return () => { gone = true; cleanups.forEach((c) => c()); stage?.dispose(); setReady(false); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [forceTier, ambient, particleScale, idleSpin, hoverLayers]);

  return (
    <div ref={boxRef} className={`absolute inset-0 ${className}`}>
      <div className="absolute inset-0 grid place-items-center transition-opacity duration-700" style={{ opacity: ready ? 0 : 1 }}>
        <LabyrinthMark className="h-[72%] w-[72%]" decorative />
      </div>
      <canvas ref={canvasRef} aria-hidden="true" className="absolute inset-0 size-full transition-opacity duration-700" style={{ opacity: ready ? 1 : 0 }} />
      <div ref={tipRef} aria-hidden className="pointer-events-none absolute left-0 top-0 z-10 rounded-[var(--radius-chip)] bg-ink-3 px-2 py-1 text-xs text-bone opacity-0 transition-opacity" />
      <p className="sr-only-text">{label}</p>
    </div>
  );
}

export { tierConfig };
