import * as THREE from "three";
import { Disposer } from "./dispose";
import { pickTier, stepDown, tierConfig, type Tier, type TierConfig } from "./quality";

export type FrameCb = (dt: number, t: number) => void;

export interface StageOptions {
  canvas: HTMLCanvasElement;
  container: HTMLElement;
  tier?: Tier;
  fpsCap?: number;
  alpha?: boolean;
  govern?: boolean;
  /** render single frames only (reduced motion): never starts the RAF loop */
  staticFrame?: boolean;
  onContextLost?: () => void;
}

/**
 * One renderer and one RAF loop per canvas. Children register per-frame callbacks and
 * disposables. Pauses when offscreen or in a hidden tab; steps quality down on a slow CPU.
 */
export class Stage {
  readonly scene = new THREE.Scene();
  readonly camera = new THREE.PerspectiveCamera(32, 1, 0.1, 100);
  readonly renderer: THREE.WebGLRenderer;
  readonly disposer = new Disposer();
  cfg: TierConfig;

  private cbs = new Set<FrameCb>();
  private raf = 0;
  private last = 0;
  private lastRender = 0;
  private visible = true;
  private running = false;
  private elapsed = 0;
  private ro: ResizeObserver;
  private io: IntersectionObserver;
  private slowFrames = 0;
  private onVis = () => this.sync();
  private onLost = (e: Event) => { e.preventDefault(); this.stop(); this.opts.onContextLost?.(); };
  private frameInterval: number;
  onTierChange?: (c: TierConfig) => void;

  constructor(private opts: StageOptions) {
    this.cfg = tierConfig(opts.tier ?? pickTier());
    this.frameInterval = opts.fpsCap ? 1000 / opts.fpsCap : 0;
    this.renderer = new THREE.WebGLRenderer({
      canvas: opts.canvas,
      antialias: this.cfg.antialias,
      alpha: opts.alpha ?? true,
      powerPreference: "high-performance",
    });
    this.renderer.setClearColor(0x000000, 0);
    this.applySize();

    this.ro = new ResizeObserver(() => this.applySize());
    this.ro.observe(opts.container);
    this.io = new IntersectionObserver(([e]) => { this.visible = e.isIntersecting; this.sync(); }, { threshold: 0 });
    this.io.observe(opts.container);
    document.addEventListener("visibilitychange", this.onVis);
    opts.canvas.addEventListener("webglcontextlost", this.onLost);
  }

  onFrame(cb: FrameCb) { this.cbs.add(cb); return () => this.cbs.delete(cb); }

  private applySize() {
    const { clientWidth: w, clientHeight: h } = this.opts.container;
    if (!w || !h) return;
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, this.cfg.dprCap));
    this.renderer.setSize(w, h, false);
    this.camera.aspect = w / h;
    this.camera.updateProjectionMatrix();
    this.invalidate();
  }

  private sync() {
    const shouldRun = this.visible && !document.hidden && !this.opts.staticFrame;
    if (shouldRun && !this.running) this.start();
    else if (!shouldRun && this.running) this.stop();
  }

  start() {
    if (this.running) return;
    this.running = true;
    this.last = performance.now();
    this.raf = requestAnimationFrame(this.loop);
  }
  stop() { this.running = false; cancelAnimationFrame(this.raf); }

  /** Render a single frame (used for reduced motion and after resize while paused). */
  invalidate() { if (!this.running) this.renderOnce(); }

  renderOnce(dt = 0) {
    this.elapsed += dt;
    this.cbs.forEach((cb) => cb(dt, this.elapsed));
    this.renderer.render(this.scene, this.camera);
  }

  private loop = (now: number) => {
    if (!this.running) return;
    this.raf = requestAnimationFrame(this.loop);
    if (this.frameInterval && now - this.lastRender < this.frameInterval - 1) return;
    this.lastRender = now;
    const dtMs = now - this.last;
    this.last = now;
    const dt = Math.min(dtMs / 1000, 0.1);

    if (this.opts.govern) {
      // runtime governor: sustained long frames step the tier down once
      if (dtMs > 34) this.slowFrames++; else this.slowFrames = Math.max(0, this.slowFrames - 1);
      if (this.slowFrames > 45 && this.cfg.tier !== "low") {
        this.cfg = tierConfig(stepDown(this.cfg.tier));
        this.slowFrames = 0;
        this.applySize();
        this.onTierChange?.(this.cfg);
      }
    }
    this.renderOnce(dt);
  };

  dispose(routeExit = false) {
    this.stop();
    this.ro.disconnect();
    this.io.disconnect();
    document.removeEventListener("visibilitychange", this.onVis);
    this.opts.canvas.removeEventListener("webglcontextlost", this.onLost);
    this.cbs.clear();
    this.disposer.run();
    this.scene.traverse((o) => {
      const m = o as THREE.Mesh;
      m.geometry?.dispose?.();
      const mat = m.material as THREE.Material | THREE.Material[] | undefined;
      if (Array.isArray(mat)) mat.forEach((x) => x.dispose()); else mat?.dispose?.();
    });
    this.renderer.dispose();
    if (routeExit) this.renderer.forceContextLoss();
    if (process.env.NODE_ENV !== "production") {
      // dev-only assertion: memory should return to zero after a mount/unmount cycle
      const { geometries, textures } = this.renderer.info.memory;
      if (geometries || textures) console.debug("[dida/three] disposal check", { geometries, textures });
    }
  }
}
