precision highp float;
varying float vAlpha;
varying float vAttack;
varying float vFlare;
uniform vec3 uBone;
uniform vec3 uSignal;
void main() {
  vec2 c = gl_PointCoord - 0.5;
  float d = length(c);
  float soft = smoothstep(0.5, 0.0, d);
  vec3 col = mix(uBone * 0.8, uSignal, vAttack);
  col += uSignal * vFlare * 0.8;
  gl_FragColor = vec4(col, soft * vAlpha);
}
