"use client";
import { useRef, type ReactNode } from "react";
import { useGsap } from "@/hooks/useGsap";
import { createTiltInteraction } from "@/lib/animations/interactions";

export function TiltCard({ children, className, max = 4 }: { children: ReactNode; className?: string; max?: number }) {
  const ref = useRef<HTMLDivElement>(null);
  useGsap(ref, () => (ref.current ? createTiltInteraction(ref.current, { max }) : undefined), [max]);
  return <div ref={ref} className={className}>{children}</div>;
}
