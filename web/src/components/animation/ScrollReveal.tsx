"use client";
import { useRef, type ReactNode, type ElementType } from "react";
import { useGsap } from "@/hooks/useGsap";
import { animateIn, staggerReveal } from "@/lib/animations/core";
import { onEnter } from "@/lib/animations/scroll";

/** Reveals children once when they enter. `children` mode staggers direct children. */
export function ScrollReveal({ children, as: Tag = "div", className, y = 18, delay = 0, stagger = false, start = "top 82%" }: {
  children: ReactNode; as?: ElementType; className?: string; y?: number; delay?: number; stagger?: boolean; start?: string;
}) {
  const ref = useRef<HTMLElement>(null);
  useGsap(ref, () => {
    const el = ref.current; if (!el) return;
    const targets = stagger ? Array.from(el.children) : el;
    return onEnter(el, () => (stagger ? staggerReveal(targets, { y }) : animateIn(targets, { y, delay })), start);
  }, []);
  const Comp = Tag as ElementType;
  const attr = stagger ? { "data-reveal-children": "" } : { "data-reveal": "" };
  return <Comp ref={ref} {...attr} className={className}>{children}</Comp>;
}
