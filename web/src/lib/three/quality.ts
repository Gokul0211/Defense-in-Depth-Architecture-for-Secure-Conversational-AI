export type Tier = "high" | "medium" | "low";

export interface TierConfig {
  tier: Tier; dprCap: number; particles: number; octaves: number;
  antialias: boolean; raycast: boolean; bgFps: number; lineDensity: number;
}

const CONFIGS: Record<Tier, Omit<TierConfig, "tier">> = {
  high:   { dprCap: 2,   particles: 6000, octaves: 4, antialias: true,  raycast: true,  bgFps: 30, lineDensity: 14 },
  medium: { dprCap: 1.5, particles: 2500, octaves: 3, antialias: false, raycast: false, bgFps: 30, lineDensity: 12 },
  low:    { dprCap: 1,   particles: 800,  octaves: 2, antialias: false, raycast: false, bgFps: 24, lineDensity: 9 },
};

export function pickTier(): Tier {
  if (typeof window === "undefined") return "low";
  const fine = window.matchMedia("(pointer: fine)").matches;
  const cores = navigator.hardwareConcurrency ?? 4;
  const mem = (navigator as Navigator & { deviceMemory?: number }).deviceMemory ?? 4;
  const w = window.innerWidth;
  if (!fine || w < 768) return "low";
  if (fine && (cores >= 8 || mem >= 8) && w >= 1280) return "high";
  return "medium";
}

export const tierConfig = (t: Tier): TierConfig => ({ tier: t, ...CONFIGS[t] });
export const stepDown = (t: Tier): Tier => (t === "high" ? "medium" : "low");
