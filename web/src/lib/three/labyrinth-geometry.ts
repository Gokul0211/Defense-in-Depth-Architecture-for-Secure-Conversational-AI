import * as THREE from "three";

/** Same numbers as assets/logo/build_logo.py. SVG units: 1 unit = SCALE world units. */
export const WALLS = 5;
export const STEP = 16;
export const OUTER_R = 80;
export const STROKE = 9;
export const GAP = 17;
export const OPENINGS = [0.21, 0.5, 0.79, 0.93, 0.385] as const;
export const SCALE = 0.04;
export const WALL_HEIGHT = 1.0;

export const wallRadius = (k: number) => OUTER_R - k * STEP;

type V2 = [number, number];

/** Point on the D centreline at arc length s (SVG units, centred on the arc centre, y up). */
function pointAt(r: number, s: number): V2 {
  const per = r * (4 + Math.PI);
  s = ((s % per) + per) % per;
  // path: start (-r, 0) up to (-r, r), right to (0, r), clockwise arc to (0, -r), left to (-r, -r), up to start
  if (s <= r) return [-r, s];
  s -= r;
  if (s <= r) return [-r + s, r];
  s -= r;
  if (s <= Math.PI * r) { const a = Math.PI / 2 - s / r; return [r * Math.cos(a), r * Math.sin(a)]; }
  s -= Math.PI * r;
  if (s <= r) return [-s, -r];
  s -= r;
  return [-r, -r + s];
}

/** One wall: a thick open ring (miter joins) extruded upward, with a single opening. */
export function buildWallGeometry(k: number, height = WALL_HEIGHT): THREE.BufferGeometry {
  const r = wallRadius(k);
  const per = r * (4 + Math.PI);
  const gapStart = OPENINGS[k] * per - GAP / 2;
  const gapEnd = OPENINGS[k] * per + GAP / 2;

  // run from gapEnd around to gapStart + per
  const s0 = gapEnd, s1 = gapStart + per;
  const breaks = [r, 2 * r, 2 * r + Math.PI * r, 3 * r + Math.PI * r, 4 * r + Math.PI * r];
  const ss: number[] = [s0];
  const arcStep = Math.max(1.2, r / 22);
  const marks = new Set<number>();
  for (const b of breaks) for (const m of [0, 1]) { const v = b + m * per; if (v > s0 + 1e-6 && v < s1 - 1e-6) marks.add(v); }
  [...marks].sort((a, b) => a - b).forEach((m) => ss.push(m));
  ss.push(s1);
  const dense: number[] = [];
  for (let i = 0; i < ss.length - 1; i++) {
    dense.push(ss[i]);
    const seg = ss[i + 1] - ss[i];
    const n = Math.floor(seg / arcStep);
    for (let j = 1; j < n; j++) dense.push(ss[i] + (seg * j) / n);
  }
  dense.push(s1);

  const pts = dense.map((s) => pointAt(r, s));
  const half = STROKE / 2;
  const left: V2[] = [], right: V2[] = [];
  for (let i = 0; i < pts.length; i++) {
    const prev = pts[Math.max(0, i - 1)], next = pts[Math.min(pts.length - 1, i + 1)];
    const cur = pts[i];
    const seg = (a: V2, b: V2): V2 => { const dx = b[0] - a[0], dy = b[1] - a[1]; const l = Math.hypot(dx, dy) || 1; return [-dy / l, dx / l]; };
    const nA = i === 0 ? seg(cur, next) : seg(prev, cur);
    const nB = i === pts.length - 1 ? seg(prev, cur) : seg(cur, next);
    let nx = nA[0] + nB[0], ny = nA[1] + nB[1];
    const nl = Math.hypot(nx, ny) || 1; nx /= nl; ny /= nl;
    const miter = half / Math.max(0.2, nx * nA[0] + ny * nA[1]);
    left.push([cur[0] + nx * miter, cur[1] + ny * miter]);
    right.push([cur[0] - nx * miter, cur[1] - ny * miter]);
  }

  const shape = new THREE.Shape();
  shape.moveTo(left[0][0] * SCALE, left[0][1] * SCALE);
  for (let i = 1; i < left.length; i++) shape.lineTo(left[i][0] * SCALE, left[i][1] * SCALE);
  for (let i = right.length - 1; i >= 0; i--) shape.lineTo(right[i][0] * SCALE, right[i][1] * SCALE);
  shape.closePath();

  const geo = new THREE.ExtrudeGeometry(shape, { depth: height, bevelEnabled: false, curveSegments: 1, steps: 1 });
  // shape lives in XY (y up in logo space); stand it on the floor: logo y -> world -z, extrusion -> +y
  geo.rotateX(-Math.PI / 2);
  geo.computeVertexNormals();
  return geo;
}

/** Radii (world units) used by the particle shader: the six stops from outside to the core. */
export const particleRadii = (): number[] => [
  ...Array.from({ length: WALLS }, (_, k) => (wallRadius(k) + STROKE) * SCALE),
  0.12,
];

/** Where each wall's opening sits in world space (for the CTA path trace). */
export function openingWorldPos(k: number): THREE.Vector3 {
  const r = wallRadius(k);
  const per = r * (4 + Math.PI);
  const [x, y] = pointAt(r, OPENINGS[k] * per);
  return new THREE.Vector3(x * SCALE, 0, -y * SCALE);
}


/** Logo-space point (y up) at a fraction f of the perimeter of D(r). */
export function dPoint(r: number, f: number): [number, number] {
  const per = r * (4 + Math.PI);
  return pointAt(r, (((f % 1) + 1) % 1) * per);
}

/**
 * Route that threads the five openings to the core, as sampled points in the 200x200 logo viewBox.
 * It crosses wall k at OPENINGS[k] and walks the corridor midline (radius r_k - 8) to the next opening.
 * D(r) shapes are uniform scalings of one another, so fraction f maps to a scaled point.
 * `marks[k]` is the fraction of total path length at which wall k is crossed.
 */
export function buildTrace(): { d: string; marks: number[]; points: [number, number][] } {
  const sc = (r: number, f: number): [number, number] => { const [x, y] = dPoint(1, f); return [100 + x * r, 100 - y * r]; };
  const pts: [number, number][] = [];
  const crossIdx: number[] = [];
  pts.push(sc(wallRadius(0) + 16, OPENINGS[0]));
  for (let k = 0; k < WALLS; k++) {
    const r = wallRadius(k);
    pts.push(sc(r + 8, OPENINGS[k]));
    crossIdx.push(pts.length);
    pts.push(sc(r - 8, OPENINGS[k]));
    if (k < WALLS - 1) {
      const a = OPENINGS[k], b = OPENINGS[k + 1];
      let d = b - a; if (d > 0.5) d -= 1; if (d < -0.5) d += 1;
      const n = 36;
      for (let i = 1; i <= n; i++) pts.push(sc(r - 8, a + (d * i) / n));
    }
  }
  pts.push([100, 100]);
  const cum = [0];
  for (let i = 1; i < pts.length; i++) cum.push(cum[i - 1] + Math.hypot(pts[i][0] - pts[i - 1][0], pts[i][1] - pts[i - 1][1]));
  const total = cum[cum.length - 1];
  const marks = crossIdx.map((i) => (cum[i - 1] + cum[i]) / 2 / total);
  const d = pts.map((p, i) => `${i ? "L" : "M"}${p[0].toFixed(2)},${p[1].toFixed(2)}`).join(" ");
  return { d, marks, points: pts };
}

export function buildTracePath(): string { return buildTrace().d; }
