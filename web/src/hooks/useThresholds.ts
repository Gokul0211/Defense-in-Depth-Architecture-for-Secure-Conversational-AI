"use client";
import { useEffect, useState } from "react";
import { api } from "@/lib/api/client";
import type { Thresholds } from "@/lib/api/types";

/** Live warn/block thresholds from the running backend. Null until the backend answers. */
export function useThresholds(enabled = true): Thresholds | null {
  const [t, setT] = useState<Thresholds | null>(null);
  useEffect(() => {
    if (!enabled || t) return;
    let alive = true;
    api.thresholds().then((r) => alive && setT(r)).catch(() => {});
    return () => { alive = false; };
  }, [enabled, t]);
  return t;
}
