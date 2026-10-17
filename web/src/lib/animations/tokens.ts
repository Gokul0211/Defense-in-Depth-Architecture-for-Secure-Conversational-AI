/** Motion tokens. Durations are seconds (GSAP). Eases map to the spec's cubic-bezier curves. */
export const dur = { micro: 0.16, short: 0.26, base: 0.52, long: 0.9, scene: 1.6 } as const;
export const ease = {
  out: "expo.out",            // ~ cubic-bezier(0.16, 1, 0.3, 1)
  inOut: "power3.inOut",      // ~ cubic-bezier(0.65, 0, 0.35, 1)
  spring: "elastic.out(1, 0.55)",
} as const;
export const stagger = { char: 0.018, word: 0.045 } as const;
