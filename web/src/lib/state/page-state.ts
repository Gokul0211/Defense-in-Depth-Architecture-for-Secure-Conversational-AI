/** Tiny shared signal (no React state) so the CTA can brighten the 3D core anywhere on the page. */
type S = { ctaHover: boolean };
type L = (s: S) => void;
let state: S = { ctaHover: false };
const ls = new Set<L>();
export const pageState = {
  get: () => state,
  set: (p: Partial<S>) => { state = { ...state, ...p }; ls.forEach((l) => l(state)); },
  subscribe: (l: L) => { ls.add(l); return () => { ls.delete(l); }; },
};
