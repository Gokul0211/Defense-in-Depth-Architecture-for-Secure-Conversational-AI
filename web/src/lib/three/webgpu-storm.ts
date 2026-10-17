/**
 * EXPERIMENTAL. A WebGPU compute particle storm drawn over the hero scene. Off by default: it only runs with
 * `?gpu=1` in the URL and `navigator.gpu` present. It was written against the three.js TSL API but could not
 * be run in the build environment (no WebGPU there), so treat it as untested. Any failure disposes it and the
 * regular WebGL scene carries on unchanged.
 */
import * as THREE from "three/webgpu";
import { Fn, instancedArray, instanceIndex, vec3, float, hash, uniform, sin, cos, length, normalize, mix, smoothstep, step, select, fract, floor } from "three/tsl";
import { poseOf, type LabyrinthState } from "./labyrinth-scene";

export interface StormOptions { container: HTMLElement; state: LabyrinthState; count?: number }

export async function attachStorm({ container, state, count = 120_000 }: StormOptions): Promise<() => void> {
  const canvas = document.createElement("canvas");
  canvas.setAttribute("aria-hidden", "true");
  canvas.style.cssText = "position:absolute;inset:0;width:100%;height:100%;pointer-events:none;";
  container.appendChild(canvas);

  const renderer = new THREE.WebGPURenderer({ canvas, alpha: true, antialias: false });
  await renderer.init();
  renderer.setClearColor(0x000000, 0);
  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(32, 1, 0.1, 100);

  const positions = instancedArray(count, "vec3");
  const velocities = instancedArray(count, "vec3");
  const uProbe = uniform(new THREE.Vector3(99, 0, 99));
  const uAmt = uniform(0);
  const uDt = uniform(0.016);
  const uTime = uniform(0);

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const spawn = (salt: any) => {
    const h1 = hash(instanceIndex.toFloat().add(salt));
    const h2 = hash(instanceIndex.toFloat().add(salt).add(7919));
    const h3 = hash(instanceIndex.toFloat().add(salt).add(104729));
    const ang = h1.mul(6.2831853);
    const r = h2.mul(2.4).add(4.6);
    return vec3(cos(ang).mul(r), h3.mul(0.8).add(0.05), sin(ang).mul(r));
  };

  const init = Fn(() => {
    positions.element(instanceIndex).assign(spawn(float(0)));
    velocities.element(instanceIndex).assign(vec3(0, 0, 0));
  })().compute(count);

  const update = Fn(() => {
    const p = positions.element(instanceIndex);
    const v = velocities.element(instanceIndex);
    const h2 = hash(instanceIndex.toFloat().add(7919));
    const h4 = hash(instanceIndex.toFloat().add(15485863));
    const stopR = h4.mul(3.0).add(0.5);                       // radius where this particle halts
    const r = length(vec3(p.x, 0, p.z));
    const inward = normalize(vec3(p.x.negate(), 0, p.z.negate()));
    const swirl = normalize(vec3(p.z.negate(), 0, p.x));
    const accel = smoothstep(stopR, stopR.add(0.4), r);        // 1 outside its stop radius, 0 at it
    const away = p.sub(uProbe);
    const push = smoothstep(1.5, 0.0, length(away)).mul(uAmt);
    const nv = v.mul(0.965).add(inward.mul(accel.mul(uDt).mul(3.2))).add(swirl.mul(uDt).mul(0.7)).add(normalize(away).mul(push.mul(uDt).mul(20)));
    v.assign(nv);
    const np = p.add(nv.mul(uDt));
    const life = fract(uTime.mul(0.07).add(h2));
    const respawn = life.lessThan(uDt.mul(0.12));
    p.assign(select(respawn, spawn(floor(uTime.mul(3))), np));
  })().compute(count);

  const material = new THREE.SpriteNodeMaterial({ transparent: true, depthWrite: false, blending: THREE.AdditiveBlending });
  material.positionNode = positions.toAttribute();
  material.scaleNode = float(0.018);
  material.colorNode = mix(vec3(0.94, 0.92, 0.89), vec3(1.0, 0.31, 0.12), step(0.84, hash(instanceIndex.toFloat())));
  material.opacityNode = float(0.55);
  const sprite = new THREE.Sprite(material);
  sprite.count = count;
  sprite.frustumCulled = false;
  scene.add(sprite);

  const size = () => {
    const w = container.clientWidth, h = container.clientHeight; if (!w || !h) return;
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.5));
    renderer.setSize(w, h, false);
    camera.aspect = w / h; camera.updateProjectionMatrix();
  };
  size();
  const ro = new ResizeObserver(size); ro.observe(container);

  await renderer.computeAsync(init);

  let raf = 0, last = performance.now(), visible = true, disposed = false;
  const io = new IntersectionObserver(([e]) => { visible = e.isIntersecting; }); io.observe(container);
  const frame = (now: number) => {
    if (disposed) return;
    raf = requestAnimationFrame(frame);
    if (!visible || document.hidden) { last = now; return; }
    const dt = Math.min(0.05, (now - last) / 1000); last = now;
    uDt.value = dt; uTime.value += dt;
    uProbe.value.set(state.probe.x, 0, state.probe.z); uAmt.value = state.probe.amt;
    const [x, y, z] = poseOf(state, camera.aspect, (3 * Math.PI) / 180);
    camera.position.set(x, y, z); camera.lookAt(0, state.cam.targetY, 0);
    renderer.compute(update);
    renderer.render(scene, camera);
  };
  raf = requestAnimationFrame(frame);

  return () => {
    disposed = true; cancelAnimationFrame(raf); ro.disconnect(); io.disconnect();
    try { renderer.dispose(); } catch { /* already gone */ }
    canvas.remove();
  };
}
