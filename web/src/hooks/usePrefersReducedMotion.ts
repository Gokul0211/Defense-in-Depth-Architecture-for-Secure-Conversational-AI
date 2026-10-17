"use client";
import { useSyncExternalStore } from "react";

const q = () => window.matchMedia("(prefers-reduced-motion: reduce)");
export function usePrefersReducedMotion() {
  return useSyncExternalStore(
    (cb) => { const m = q(); m.addEventListener("change", cb); return () => m.removeEventListener("change", cb); },
    () => q().matches,
    () => false,
  );
}
