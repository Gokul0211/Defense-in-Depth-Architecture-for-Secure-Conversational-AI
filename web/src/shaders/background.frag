// Contour field: slow topographic hairlines from domain-warped noise, bone on ink,
// with a faint signal-orange pool where the labyrinth sits. OCTAVES is injected as a #define.
precision highp float;
varying vec2 vUv;

uniform float uTime;
uniform vec2  uResolution;
uniform vec2  uPointer;          // 0..1, eased on the JS side
uniform float uPointerStrength;  // 0..0.15
uniform float uIntro;            // 0..1 fade from black
uniform float uScroll;           // 0..1 page progress
uniform float uLineDensity;
uniform vec2  uAccentPos;        // 0..1
uniform float uAccentStrength;   // 0..0.25
uniform float uGrain;

vec2 hash2(vec2 p) {
  p = vec2(dot(p, vec2(127.1, 311.7)), dot(p, vec2(269.5, 183.3)));
  return -1.0 + 2.0 * fract(sin(p) * 43758.5453123);
}
float noise(vec2 p) {
  vec2 i = floor(p), f = fract(p);
  vec2 u = f * f * f * (f * (f * 6.0 - 15.0) + 10.0);
  return mix(mix(dot(hash2(i + vec2(0, 0)), f - vec2(0, 0)),
                 dot(hash2(i + vec2(1, 0)), f - vec2(1, 0)), u.x),
             mix(dot(hash2(i + vec2(0, 1)), f - vec2(0, 1)),
                 dot(hash2(i + vec2(1, 1)), f - vec2(1, 1)), u.x), u.y);
}
float fbm(vec2 p) {
  float v = 0.0, a = 0.5;
  mat2 r = mat2(0.8, -0.6, 0.6, 0.8);
  for (int i = 0; i < OCTAVES; i++) { v += a * noise(p); p = r * p * 2.0; a *= 0.5; }
  return v;
}

void main() {
  float aspect = uResolution.x / uResolution.y;
  vec2 uv = vUv; uv.x *= aspect;
  vec2 ptr = uPointer; ptr.x *= aspect;

  // flow direction rotates slightly with page progress
  float ang = uScroll * 0.6;
  mat2 rot = mat2(cos(ang), -sin(ang), sin(ang), cos(ang));
  vec2 p = rot * uv * 1.15;

  // contours bend toward the pointer
  vec2 toPtr = ptr - uv;
  float pull = uPointerStrength * exp(-dot(toPtr, toPtr) * 5.0);
  p += toPtr * pull;

  float t = uTime * 0.025;
  vec2 q = vec2(fbm(p + vec2(0.0, t)), fbm(p + vec2(5.2, 1.3) - t));
  float h = fbm(p + 1.6 * q + vec2(t, -t * 0.7));

  // hairline contours with screen-space width
  float f = h * uLineDensity;
  float w = fwidth(f);
  float d = abs(fract(f) - 0.5);                    // 0 at the ridge, 0.5 between lines
  float hair = 1.0 - smoothstep(0.0, w * 1.4 + 0.004, d);
  hair = clamp(hair, 0.0, 1.0);

  vec3 ink = vec3(0.043, 0.043, 0.047);
  vec3 bone = vec3(0.937, 0.922, 0.890);
  vec3 signal = vec3(1.0, 0.31, 0.12);

  vec2 ap = uAccentPos; ap.x *= aspect;
  float pool = exp(-dot(uv - ap, uv - ap) * 2.4);

  vec3 col = ink;
  col += bone * hair * (0.055 + 0.05 * pool);
  col += signal * pool * (0.035 + uAccentStrength * 0.6);
  col += signal * hair * pool * uAccentStrength * 0.8;

  // vignette keeps edges calm
  float vig = smoothstep(1.25, 0.25, length(vUv - 0.5) * 1.4);
  col *= mix(0.55, 1.0, vig);

  // dither against banding
  float n = fract(sin(dot(gl_FragCoord.xy, vec2(12.9898, 78.233))) * 43758.5453);
  col += (n - 0.5) * uGrain / 255.0;

  gl_FragColor = vec4(col * uIntro, 1.0);
}
