"use client";
import { useEffect, useState } from "react";
import { api } from "@/lib/api/client";
import type { Health } from "@/lib/api/types";

export type HealthState = { status: "checking" } | { status: "online"; health: Health } | { status: "offline" };

export function useApiHealth(intervalMs = 8000): HealthState {
  const [state, setState] = useState<HealthState>({ status: "checking" });
  useEffect(() => {
    let alive = true;
    const tick = () => api.health().then((health) => alive && setState({ status: "online", health })).catch(() => alive && setState({ status: "offline" }));
    tick();
    const id = setInterval(tick, intervalMs);
    return () => { alive = false; clearInterval(id); };
  }, [intervalMs]);
  return state;
}
