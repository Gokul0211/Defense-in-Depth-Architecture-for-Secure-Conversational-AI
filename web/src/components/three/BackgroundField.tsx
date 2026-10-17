"use client";
import { useEffect, useRef } from "react";
import * as THREE from "three";
import { Stage } from "@/lib/three/stage";
import { pickTier, tierConfig } from "@/lib/three/quality";
import { motion, prefersReducedMotion, ScrollTrigger } from "@/lib/animations/core";
import { pageState } from "@/lib/state/page-state";
import vert from "@/shaders/background.vert";
import frag from "@/shaders/background.frag";

/** Fixed contour-field shader behind the content. 30 fps cap, pauses when the tab is hidden. */
export default function BackgroundField() {
  const boxRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const box = boxRef.current, canvas = canvasRef.current;
    if (!box || !canvas) return;
    const reduced = prefersReducedMotion();
    const cfg = tierConfig(pickTier());
    let stage: Stage | null = null;
    const cleanups: Array<() => void> = [];
    try {
      stage = new Stage({ canvas, container: box, tier: cfg.tier, fpsCap: cfg.bgFps, alpha: false, staticFrame: reduced });
      const geo = stage.disposer.add(new THREE.BufferGeometry());
      geo.setAttribute("position", new THREE.BufferAttribute(new Float32Array([-1, -1, 0, 3, -1, 0, -1, 3, 0]), 3));
      const u = {
        uTime: { value: 0 }, uResolution: { value: new THREE.Vector2(1, 1) }, uPointer: { value: new THREE.Vector2(0.5, 0.5) },
        uPointerStrength: { value: 0.1 }, uIntro: { value: reduced ? 1 : 0 }, uScroll: { value: 0 },
        uLineDensity: { value: cfg.lineDensity }, uAccentPos: { value: new THREE.Vector2(0.72, 0.5) },
        uAccentStrength: { value: 0.06 }, uGrain: { value: 2.0 },
      };
      const mat = stage.disposer.add(new THREE.ShaderMaterial({ vertexShader: vert, fragmentShader: frag, uniforms: u, defines: { OCTAVES: cfg.octaves }, depthTest: false, depthWrite: false }));
      const mesh = new THREE.Mesh(geo, mat);
      mesh.frustumCulled = false;
      stage.scene.add(mesh);

      const ptr = { x: 0.5, y: 0.5 };
      const px = motion.quickTo(ptr, "x", { duration: 1.2, ease: "power3.out" });
      const py = motion.quickTo(ptr, "y", { duration: 1.2, ease: "power3.out" });
      if (!reduced) {
        const move = (e: PointerEvent) => { px(e.clientX / window.innerWidth); py(1 - e.clientY / window.innerHeight); };
        window.addEventListener("pointermove", move, { passive: true });
        cleanups.push(() => window.removeEventListener("pointermove", move));
        motion.to(u.uIntro, { value: 1, duration: 1.4, ease: "power2.out" });
        const st = ScrollTrigger.create({ trigger: document.body, start: "top top", end: "bottom bottom", onUpdate: (s) => { u.uScroll.value = s.progress; } });
        cleanups.push(() => st.kill());
        cleanups.push(pageState.subscribe((s) => { motion.to(u.uAccentStrength, { value: s.ctaHover ? 0.22 : 0.06, duration: 0.6, ease: "power2.out", overwrite: "auto" }); }));
      }

      let tick = 0;
      stage.onFrame((_dt, t) => {
        u.uTime.value = t;
        u.uResolution.value.set(stage!.renderer.domElement.width, stage!.renderer.domElement.height);
        u.uPointer.value.set(ptr.x, ptr.y);
        // follow the labyrinth: any element marked data-accent-anchor
        if (tick++ % 8 === 0) {
          const a = document.querySelector("[data-accent-anchor]");
          if (a) { const r = a.getBoundingClientRect(); u.uAccentPos.value.set((r.left + r.width / 2) / window.innerWidth, 1 - (r.top + r.height / 2) / window.innerHeight); }
        }
      });
      stage.renderOnce();
      if (!reduced) stage.start();
    } catch (err) {
      console.warn("[dida] background shader unavailable", err);
    }
    return () => { cleanups.forEach((c) => c()); stage?.dispose(); };
  }, []);

  return (
    <div ref={boxRef} aria-hidden="true" className="pointer-events-none fixed inset-0" style={{ zIndex: 0 }}>
      <canvas ref={canvasRef} className="size-full" />
    </div>
  );
}
