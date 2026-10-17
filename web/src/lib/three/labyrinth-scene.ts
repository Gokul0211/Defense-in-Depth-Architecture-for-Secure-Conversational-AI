import * as THREE from "three";
import { Stage } from "./stage";
import { SCALE, WALLS, WALL_HEIGHT, buildWallGeometry, particleRadii, wallRadius, STROKE } from "./labyrinth-geometry";
import wallsVert from "@/shaders/walls.vert";
import wallsFrag from "@/shaders/walls.frag";
import particlesVert from "@/shaders/particles.vert";
import particlesFrag from "@/shaders/particles.frag";
import glowVert from "@/shaders/glow.vert";
import glowFrag from "@/shaders/glow.frag";

const BONE = new THREE.Color("#efebe3");
const SIGNAL = new THREE.Color("#ff4f1f");

/** Mutable state read each frame. GSAP writes to it; React never touches it. */
export interface LabyrinthState {
  rise: number[];          // 0..1 per wall
  highlight: number[];     // 0..1 per wall
  dim: number;             // 0..1 dims non-highlighted walls
  core: number;            // 0..1 core brightness
  pulse: number;           // 0..1 transient pulse
  evidence: number;        // 0..1 evidence line progress
  flare: number;           // 0..1 global particle flare
  pointer: { x: number; y: number };
  cam: { azimuth: number; elevation: number; distance: number; targetY: number };
  spin: number;            // slow idle rotation, radians
  probe: { x: number; z: number; amt: number }; // cursor probe on the floor plane
}

export const initialState = (): LabyrinthState => ({
  rise: Array(WALLS).fill(0), highlight: Array(WALLS).fill(0), dim: 0, core: 0, pulse: 0, evidence: 0, flare: 0,
  pointer: { x: 0, y: 0 },
  cam: { azimuth: 0.35, elevation: 0.62, distance: 17, targetY: 0.2 },
  spin: 0,
  probe: { x: 99, z: 99, amt: 0 },
});

/** Camera position for a given state; shared with the experimental WebGPU overlay so both line up. */
export function poseOf(state: LabyrinthState, aspect: number, parallaxRad: number): [number, number, number] {
  const az = state.cam.azimuth + state.spin + state.pointer.x * parallaxRad;
  const el = state.cam.elevation + state.pointer.y * parallaxRad * 0.6;
  const d = Math.max(state.cam.distance, 16 / aspect);
  return [Math.sin(az) * Math.cos(el) * d, Math.sin(el) * d, Math.cos(az) * Math.cos(el) * d];
}

export interface LabyrinthHandle {
  state: LabyrinthState;
  walls: THREE.Mesh[];
  root: THREE.Group;
  setParticleActivity(n: number): void;
  /** console mode: spawn a burst on a layer wall (real events only) */
  burst(wall: number, attack: boolean): void;
  setIdleSpin(on: boolean): void;
}

export interface BuildOptions {
  particles: number;
  idleSpin?: boolean;
  /** console: no ambient particles, bursts only */
  ambient?: boolean;
  parallaxDeg?: number;
}

export function buildLabyrinth(stage: Stage, opts: BuildOptions): LabyrinthHandle {
  const state = initialState();
  const root = new THREE.Group();
  stage.scene.add(root);

  // floor-less: walls only, lit by shader
  const walls: THREE.Mesh[] = [];
  const mats: THREE.ShaderMaterial[] = [];
  for (let k = 0; k < WALLS; k++) {
    const geo = stage.disposer.add(buildWallGeometry(k));
    const mat = stage.disposer.add(new THREE.ShaderMaterial({
      vertexShader: wallsVert, fragmentShader: wallsFrag,
      uniforms: { uHighlight: { value: 0 }, uDim: { value: 0 }, uHeight: { value: WALL_HEIGHT }, uBone: { value: BONE }, uSignal: { value: SIGNAL }, uProbe: { value: new THREE.Vector3(99, 0, 99) }, uProbeAmt: { value: 0 } },
      side: THREE.DoubleSide,
    }));
    const mesh = new THREE.Mesh(geo, mat);
    mesh.scale.y = 0.0001;
    mesh.name = `wall-${k}`;
    root.add(mesh); walls.push(mesh); mats.push(mat);
  }

  // protected core
  const coreGeo = stage.disposer.add(new THREE.BoxGeometry(12 * SCALE, 12 * SCALE, 12 * SCALE));
  const coreMat = stage.disposer.add(new THREE.MeshBasicMaterial({ color: SIGNAL }));
  const core = new THREE.Mesh(coreGeo, coreMat);
  core.position.y = 6 * SCALE;
  core.scale.setScalar(0.0001);
  root.add(core);

  // fake bloom: camera-facing additive sprite with a custom radial falloff
  const glowGeo = stage.disposer.add(new THREE.PlaneGeometry(3.2, 3.2));
  const glowMat = stage.disposer.add(new THREE.ShaderMaterial({
    vertexShader: glowVert, fragmentShader: glowFrag, transparent: true, depthWrite: false, blending: THREE.AdditiveBlending,
    uniforms: { uIntensity: { value: 0 }, uPulse: { value: 0 }, uSignal: { value: SIGNAL } },
  }));
  const glow = new THREE.Mesh(glowGeo, glowMat);
  glow.position.y = 0.5;
  root.add(glow);

  // evidence lines: from each wall's outer edge to the core, dash progress via geometry draw range
  const evGeo = stage.disposer.add(new THREE.BufferGeometry());
  const evPos = new Float32Array(WALLS * 2 * 3);
  for (let k = 0; k < WALLS; k++) {
    const r = (wallRadius(k) + STROKE / 2) * SCALE;
    const a = (k / WALLS) * Math.PI * 2 + 0.4;
    evPos.set([Math.cos(a) * r, WALL_HEIGHT, Math.sin(a) * r, 0, 6 * SCALE, 0], k * 6);
  }
  evGeo.setAttribute("position", new THREE.BufferAttribute(evPos, 3));
  const evMat = stage.disposer.add(new THREE.LineBasicMaterial({ color: SIGNAL, transparent: true, opacity: 0 }));
  const evidence = new THREE.LineSegments(evGeo, evMat);
  root.add(evidence);

  // particles (illustrative on the landing page, event-driven in the console)
  const count = opts.particles;
  const pGeo = stage.disposer.add(new THREE.BufferGeometry());
  const seed = new Float32Array(count), ang = new Float32Array(count), stop = new Float32Array(count), atk = new Float32Array(count);
  const pos = new Float32Array(count * 3);
  for (let i = 0; i < count; i++) {
    seed[i] = Math.random(); ang[i] = Math.random() * Math.PI * 2;
    const attack = Math.random() < 0.18;
    atk[i] = attack ? 1 : 0;
    stop[i] = attack ? Math.floor(Math.random() * 5) : Math.random() < 0.25 ? 5 : Math.floor(Math.random() * 5);
  }
  pGeo.setAttribute("position", new THREE.BufferAttribute(pos, 3));
  pGeo.setAttribute("aSeed", new THREE.BufferAttribute(seed, 1));
  pGeo.setAttribute("aAngle", new THREE.BufferAttribute(ang, 1));
  pGeo.setAttribute("aStop", new THREE.BufferAttribute(stop, 1));
  pGeo.setAttribute("aAttack", new THREE.BufferAttribute(atk, 1));
  pGeo.setDrawRange(0, opts.ambient === false ? 0 : count);
  const pMat = stage.disposer.add(new THREE.ShaderMaterial({
    vertexShader: particlesVert, fragmentShader: particlesFrag, transparent: true, depthWrite: false,
    uniforms: {
      uTime: { value: 0 }, uSize: { value: 2.4 }, uPixelRatio: { value: stage.renderer.getPixelRatio() },
      uFlareGlobal: { value: 0 }, uRadii: { value: particleRadii() }, uBone: { value: BONE }, uSignal: { value: SIGNAL },
      uProbe: { value: new THREE.Vector3(99, 0, 99) }, uProbeAmt: { value: 0 },
    },
  }));
  const points = new THREE.Points(pGeo, pMat);
  points.frustumCulled = false;
  root.add(points);

  // console bursts: small pool of short-lived points
  const BURST = 64;
  const bGeo = stage.disposer.add(new THREE.BufferGeometry());
  const bPos = new Float32Array(BURST * 3), bCol = new Float32Array(BURST * 3);
  bGeo.setAttribute("position", new THREE.BufferAttribute(bPos, 3));
  bGeo.setAttribute("color", new THREE.BufferAttribute(bCol, 3));
  const bMat = stage.disposer.add(new THREE.PointsMaterial({ size: 0.16, vertexColors: true, transparent: true, depthWrite: false, blending: THREE.AdditiveBlending }));
  const bursts = new THREE.Points(bGeo, bMat);
  bursts.frustumCulled = false;
  root.add(bursts);
  const bLife = new Float32Array(BURST), bVel = new Float32Array(BURST * 3), bBase = new Float32Array(BURST * 3);
  let bNext = 0;

  let spinOn = opts.idleSpin ?? true;
  const parallax = ((opts.parallaxDeg ?? 3) * Math.PI) / 180;
  const target = new THREE.Vector3();

  stage.onFrame((dt, t) => {
    // walls
    for (let k = 0; k < WALLS; k++) {
      walls[k].scale.y = Math.max(0.0001, state.rise[k]);
      mats[k].uniforms.uHighlight.value = state.highlight[k];
      mats[k].uniforms.uDim.value = state.dim * (1 - state.highlight[k]);
      mats[k].uniforms.uProbe.value.set(state.probe.x, 0, state.probe.z);
      mats[k].uniforms.uProbeAmt.value = state.probe.amt;
    }
    // core
    const cs = Math.max(0.0001, state.core);
    core.scale.setScalar(cs * (1 + state.pulse * 0.25));
    glowMat.uniforms.uIntensity.value = state.core;
    glowMat.uniforms.uPulse.value = state.pulse;
    glow.quaternion.copy(stage.camera.quaternion);
    // evidence
    evMat.opacity = state.evidence * 0.85;
    evGeo.setDrawRange(0, Math.round(WALLS * 2 * state.evidence));
    // particles
    pMat.uniforms.uTime.value = t;
    pMat.uniforms.uFlareGlobal.value = state.flare;
    pMat.uniforms.uProbe.value.set(state.probe.x, 0, state.probe.z);
    pMat.uniforms.uProbeAmt.value = state.probe.amt;
    pMat.uniforms.uPixelRatio.value = stage.renderer.getPixelRatio();
    // bursts: fade by scaling colour toward black (additive blending makes black invisible)
    for (let i = 0; i < BURST; i++) {
      if (bLife[i] <= 0) continue;
      bLife[i] -= dt * 1.6;
      const a = Math.max(0, bLife[i]);
      bPos[i * 3] += bVel[i * 3] * dt; bPos[i * 3 + 1] += bVel[i * 3 + 1] * dt; bPos[i * 3 + 2] += bVel[i * 3 + 2] * dt;
      bCol[i * 3] = bBase[i * 3] * a; bCol[i * 3 + 1] = bBase[i * 3 + 1] * a; bCol[i * 3 + 2] = bBase[i * 3 + 2] * a;
    }
    bGeo.attributes.position.needsUpdate = true;
    bGeo.attributes.color.needsUpdate = true;
    // idle spin + camera rig (parallax is small by rule)
    if (spinOn) state.spin += dt * 0.05;
    const az = state.cam.azimuth + state.spin + state.pointer.x * parallax;
    const el = state.cam.elevation + state.pointer.y * parallax * 0.6;
    const d = Math.max(state.cam.distance, 16 / stage.camera.aspect); // keep the outer wall in frame on narrow canvases
    stage.camera.position.set(Math.sin(az) * Math.cos(el) * d, Math.sin(el) * d, Math.cos(az) * Math.cos(el) * d);
    target.set(0, state.cam.targetY, 0);
    stage.camera.lookAt(target);
  });

  return {
    state, walls, root,
    setParticleActivity: (n) => pGeo.setDrawRange(0, Math.max(0, Math.min(count, Math.floor(n)))),
    setIdleSpin: (on) => { spinOn = on; },
    burst: (wall, attack) => {
      const r = (wallRadius(Math.min(4, Math.max(0, wall))) + STROKE / 2) * SCALE;
      for (let n = 0; n < 8; n++) {
        const i = bNext++ % BURST;
        const a = Math.random() * Math.PI * 2;
        bPos.set([Math.cos(a) * r, 0.4 + Math.random() * 0.6, Math.sin(a) * r], i * 3);
        bVel.set([-Math.cos(a) * 0.5, (Math.random() - 0.3) * 0.8, -Math.sin(a) * 0.5], i * 3);
        const c = attack ? SIGNAL : BONE;
        bBase.set([c.r, c.g, c.b], i * 3);
        bCol.set([c.r, c.g, c.b], i * 3);
        bLife[i] = 1;
      }
    },
  };
}
