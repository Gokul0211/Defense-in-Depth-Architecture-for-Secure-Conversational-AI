"use client";
import { useRef, type ComponentProps } from "react";
import { ButtonLink } from "@/components/ui/Button";
import { useGsap } from "@/hooks/useGsap";
import { createMagneticInteraction } from "@/lib/animations/interactions";
import { pageState } from "@/lib/state/page-state";

/** Primary CTA with a spring-eased magnetic pull. Hovering it brightens the 3D core via pageState. */
export function MagneticLink(props: ComponentProps<typeof ButtonLink>) {
  const ref = useRef<HTMLAnchorElement>(null);
  useGsap(ref as React.RefObject<HTMLElement>, () => (ref.current ? createMagneticInteraction(ref.current) : undefined), []);
  return (
    <span className="inline-flex" onPointerEnter={() => pageState.set({ ctaHover: true })} onPointerLeave={() => pageState.set({ ctaHover: false })} onFocus={() => pageState.set({ ctaHover: true })} onBlur={() => pageState.set({ ctaHover: false })}>
      <ButtonLink ref={ref} {...props} />
    </span>
  );
}
