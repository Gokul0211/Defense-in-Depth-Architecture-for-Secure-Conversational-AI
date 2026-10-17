"use client";
import { useRef, type ElementType } from "react";
import { useGsap } from "@/hooks/useGsap";
import { revealText, type RevealTextOpts } from "@/lib/animations/text";
import { onEnter } from "@/lib/animations/scroll";

/** Splits text and reveals it as it enters the viewport. The full string stays in aria-label. */
export function RevealText({ text, as: Tag = "span", className, onScroll = true, ...opts }: {
  text: string; as?: ElementType; className?: string; onScroll?: boolean;
} & RevealTextOpts) {
  const ref = useRef<HTMLElement>(null);
  useGsap(ref, () => {
    const el = ref.current; if (!el) return;
    const { timeline, revert } = revealText(el, { ...opts, paused: onScroll });
    const off = onScroll ? onEnter(el, () => timeline.play(), "top 85%") : () => {};
    return () => { off(); revert(); };
  }, [text]);
  const Comp = Tag as ElementType;
  return <Comp ref={ref} className={className}>{text}</Comp>;
}
