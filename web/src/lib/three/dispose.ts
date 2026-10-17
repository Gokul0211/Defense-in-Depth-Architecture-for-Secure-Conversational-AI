import * as THREE from "three";

/** Collects everything a component creates so Stage can dispose it in reverse order. */
export class Disposer {
  private items: Array<{ dispose(): void }> = [];
  add<T extends { dispose(): void }>(x: T): T { this.items.push(x); return x; }
  run() { for (let i = this.items.length - 1; i >= 0; i--) this.items[i].dispose(); this.items = []; }
}

export function disposeObject(root: THREE.Object3D) {
  root.traverse((o) => {
    const m = o as THREE.Mesh;
    m.geometry?.dispose?.();
    const mat = m.material as THREE.Material | THREE.Material[] | undefined;
    if (Array.isArray(mat)) mat.forEach((x) => x.dispose()); else mat?.dispose?.();
  });
}
