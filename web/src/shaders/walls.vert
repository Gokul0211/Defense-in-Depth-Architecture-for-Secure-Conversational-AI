varying vec3 vNormal;
varying vec3 vWorld;
varying float vY;
void main() {
  vNormal = normalize(normalMatrix * normal);
  vec4 w = modelMatrix * vec4(position, 1.0);
  vWorld = w.xyz;
  vY = position.y;
  gl_Position = projectionMatrix * viewMatrix * w;
}
