precision highp float;
varying vec3 vNormal;
varying vec3 vWorld;
varying float vY;
uniform float uHighlight;   // 0..1, this wall lit as the active layer
uniform float uDim;         // 0..1, other walls dimmed
uniform float uHeight;
uniform vec3 uBone;
uniform vec3 uSignal;
uniform vec3 uProbe;        // cursor position on the floor plane
uniform float uProbeAmt;    // 0..1
void main() {
  vec3 n = normalize(vNormal);
  vec3 keyDir = normalize(vec3(-0.5, 0.9, 0.6));
  float diff = max(dot(n, keyDir), 0.0);
  float hemi = 0.5 + 0.5 * n.y;
  float rim = pow(1.0 - abs(n.z), 2.0);
  float vgrad = clamp(vY / uHeight, 0.0, 1.0);
  vec3 base = uBone * (0.10 + 0.34 * diff + 0.10 * hemi) * mix(0.55, 1.0, vgrad);
  base *= mix(1.0, 0.35, uDim);
  // top edge catches the light
  float top = smoothstep(0.93, 1.0, vgrad);
  base += uBone * top * 0.18 * (1.0 - uDim * 0.7);
  vec3 lit = mix(base, uSignal * (0.30 + 0.38 * diff + rim * 0.18), uHighlight);
  lit += uSignal * top * 0.22 * uHighlight;
  float pg = smoothstep(1.8, 0.0, distance(vWorld.xz, uProbe.xz)) * uProbeAmt;
  lit = mix(lit, uSignal * (0.5 + 0.45 * diff), pg * 0.85);
  gl_FragColor = vec4(lit, 1.0);
}
