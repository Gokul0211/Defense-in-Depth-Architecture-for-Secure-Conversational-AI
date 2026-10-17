"use client";
import { useRef, type ReactNode } from "react";
import { useGsap } from "@/hooks/useGsap";
import { createParallaxInteraction } from "@/lib/animations/interactions";

export function ParallaxElement({ children, depth = 0.5, className }: { children: ReactNode; depth?: number; className?: string }) {
  const ref = useRef<HTMLDivElement>(null);
  useGsap(ref, () => (ref.current ? createParallaxInteraction(ref.current, { depth }) : undefined), [depth]);
  return <div ref={ref} className={className}>{children}</div>;
}
