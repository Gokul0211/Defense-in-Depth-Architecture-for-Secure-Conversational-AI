"use client";
import { useRef, type ReactNode, type CSSProperties } from "react";
import { useGsap } from "@/hooks/useGsap";
import { createSpotlightInteraction } from "@/lib/animations/interactions";
import clsx from "clsx";

/** Card whose border lights under the cursor. Details shown on hover are also shown on focus. */
export function SpotlightCard({ children, className, style, tabIndex }: { children: ReactNode; className?: string; style?: CSSProperties; tabIndex?: number }) {
  const ref = useRef<HTMLDivElement>(null);
  useGsap(ref, () => (ref.current ? createSpotlightInteraction(ref.current) : undefined), []);
  return <div ref={ref} tabIndex={tabIndex} style={style} className={clsx("spotlight", className)}>{children}</div>;
}
