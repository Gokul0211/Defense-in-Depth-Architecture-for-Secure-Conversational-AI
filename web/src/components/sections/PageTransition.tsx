"use client";
import { useEffect, useRef } from "react";
import { usePathname, useRouter } from "next/navigation";
import { LabyrinthMark } from "@/components/brand/LabyrinthMark";
import { motion, prefersReducedMotion } from "@/lib/animations/core";

/**
 * Route transition: an ink curtain with the mark slides up over the page, the route changes underneath,
 * then the curtain lifts away. Internal link clicks only. Back and forward, modified clicks, new tabs and
 * reduced motion navigate normally.
 */
export function PageTransition() {
  const router = useRouter();
  const pathname = usePathname();
  const curtain = useRef<HTMLDivElement>(null);
  const busy = useRef(false);
  const last = useRef(pathname);

  useEffect(() => {
    const el = curtain.current; if (!el) return;
    const onClick = (e: MouseEvent) => {
      if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
      const a = (e.target as Element | null)?.closest?.("a");
      if (!a || (a.target && a.target !== "_self") || a.hasAttribute("download")) return;
      const url = new URL(a.href, location.href);
      if (url.origin !== location.origin || url.pathname === location.pathname || prefersReducedMotion()) return;
      e.preventDefault();
      if (busy.current) return;
      busy.current = true;
      const to = url.pathname + url.search + url.hash;
      el.style.visibility = "visible"; el.style.pointerEvents = "auto";
      motion.set(el, { yPercent: 100 });
      motion.timeline({ onComplete: () => router.push(to) })
        .to(el, { yPercent: 0, duration: 0.45, ease: "power3.inOut" })
        .fromTo(el.querySelector("svg"), { scale: 0.85, opacity: 0 }, { scale: 1, opacity: 1, duration: 0.3, ease: "expo.out" }, 0.25);
      // if the route never changes (an error), do not trap the user behind the curtain
      window.setTimeout(() => { if (busy.current && location.pathname !== url.pathname) release(); }, 4000);
    };
    const release = () => {
      motion.to(el, { yPercent: -100, duration: 0.5, ease: "power3.inOut", onComplete: () => { el.style.visibility = "hidden"; el.style.pointerEvents = "none"; motion.set(el, { yPercent: 100 }); busy.current = false; } });
    };
    (el as HTMLDivElement & { _release?: () => void })._release = release;
    document.addEventListener("click", onClick, true);
    return () => document.removeEventListener("click", onClick, true);
  }, [router]);

  // the new route has rendered: lift the curtain
  useEffect(() => {
    if (pathname === last.current) return;
    last.current = pathname;
    const el = curtain.current as (HTMLDivElement & { _release?: () => void }) | null;
    if (el && busy.current) requestAnimationFrame(() => el._release?.());
  }, [pathname]);

  return (
    <div ref={curtain} aria-hidden="true" className="fixed inset-0 grid place-items-center bg-ink-0" style={{ zIndex: 55, visibility: "hidden", pointerEvents: "none" }}>
      <LabyrinthMark decorative className="size-28" />
    </div>
  );
}
