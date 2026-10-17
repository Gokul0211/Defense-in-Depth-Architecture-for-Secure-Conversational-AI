// Radial falloff for the protected core. Additive, depth-write off. The only bloom in the project.
precision highp float;
varying vec2 vUv;
uniform float uIntensity;
uniform float uPulse;
uniform vec3 uSignal;
void main() {
  float d = length(vUv - 0.5) * 2.0;
  float falloff = pow(max(1.0 - d, 0.0), 2.6);
  float core = pow(max(1.0 - d * 2.2, 0.0), 2.0);
  float a = (falloff * 0.55 + core * 0.9) * uIntensity * (1.0 + uPulse * 0.6);
  gl_FragColor = vec4(uSignal * a, a);
}
