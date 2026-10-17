"use client";
import { useSyncExternalStore } from "react";

const Q = "(min-width: 1024px)";
/** True at the lg breakpoint and up. The server snapshot is true so desktop never flashes the mobile layout. */
export function useIsDesktop() {
  return useSyncExternalStore(
    (cb) => { const m = window.matchMedia(Q); m.addEventListener("change", cb); return () => m.removeEventListener("change", cb); },
    () => window.matchMedia(Q).matches,
    () => true,
  );
}
