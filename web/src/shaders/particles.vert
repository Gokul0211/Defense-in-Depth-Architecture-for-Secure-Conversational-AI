// Request particles drift inward along a radial path and stop at a wall. Attack-tagged
// particles stop and flare. Illustrative on the landing page; real events in the console.
attribute float aSeed;
attribute float aAngle;
attribute float aStop;     // radius index 0..5 where this particle stops (5 = reaches core)
attribute float aAttack;   // 0 or 1
uniform float uTime;
uniform float uSize;
uniform float uPixelRatio;
uniform float uFlareGlobal;
uniform vec3 uProbe;
uniform float uProbeAmt;
uniform float uRadii[6];
varying float vAlpha;
varying float vAttack;
varying float vFlare;

float radiusFor(float idx) {
  int i = int(idx + 0.5);
  float r = uRadii[0];
  if (i == 1) r = uRadii[1]; else if (i == 2) r = uRadii[2];
  else if (i == 3) r = uRadii[3]; else if (i == 4) r = uRadii[4]; else if (i == 5) r = uRadii[5];
  return r;
}

void main() {
  float cyc = fract(aSeed + uTime * (0.05 + 0.04 * fract(aSeed * 7.0)));
  float travel = smoothstep(0.0, 0.85, cyc);
  float rStop = radiusFor(aStop);
  float r = mix(uRadii[0] * 1.55, rStop, travel);
  float a = aAngle + sin(uTime * 0.2 + aSeed * 6.28) * 0.05;
  vec3 pos = vec3(cos(a) * r, 0.12 + 0.5 * fract(aSeed * 13.0), sin(a) * r);

  vec2 pd = pos.xz - uProbe.xz;
  float pl = length(pd);
  pos.xz += normalize(pd + vec2(1e-4)) * smoothstep(1.5, 0.0, pl) * 0.55 * uProbeAmt;

  float arrived = smoothstep(0.82, 0.9, cyc);
  float fade = 1.0 - smoothstep(0.93, 1.0, cyc);
  vFlare = aAttack * arrived * fade * (0.6 + uFlareGlobal);
  vAlpha = (smoothstep(0.0, 0.08, cyc) * fade) * (aAttack > 0.5 ? 0.9 : 0.5);
  vAttack = aAttack;

  vec4 mv = modelViewMatrix * vec4(pos, 1.0);
  gl_PointSize = uSize * uPixelRatio * (1.0 + vFlare * 2.2) * (14.0 / -mv.z);
  gl_Position = projectionMatrix * mv;
}
