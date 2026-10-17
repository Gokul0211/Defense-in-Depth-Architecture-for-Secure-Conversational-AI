"use client";
import { useEffect, type RefObject } from "react";
import { motion } from "@/lib/animations/core";

/**
 * Scoped animation setup. Everything created inside `setup` is reverted on unmount,
 * which keeps React StrictMode double-mounting safe.
 */
export function useGsap(scope: RefObject<HTMLElement | null>, setup: () => void | (() => void), deps: unknown[] = []) {
  useEffect(() => {
    let cleanup: void | (() => void);
    const ctx = motion.context(() => { cleanup = setup(); }, scope.current ?? undefined);
    return () => { if (typeof cleanup === "function") cleanup(); ctx.revert(); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
}
