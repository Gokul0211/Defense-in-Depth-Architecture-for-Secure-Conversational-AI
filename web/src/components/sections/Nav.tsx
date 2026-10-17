"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { List, X } from "@phosphor-icons/react";
import { Wordmark } from "@/components/brand/Wordmark";
import { MagneticLink } from "@/components/animation/MagneticButton";
import { ROUTES, GITHUB_URL } from "@/lib/constants/routes";
import { motion, ScrollTrigger, prefersReducedMotion } from "@/lib/animations/core";
import { dur, ease } from "@/lib/animations/tokens";
import clsx from "clsx";

const LINKS = [
  { href: ROUTES.layers, label: "Layers", key: "layers" },
  { href: ROUTES.research, label: "Research", key: "research" },
  { href: ROUTES.playground, label: "Playground", key: "playground" },
] as const;

export function Nav() {
  const pathname = usePathname();
  const navRef = useRef<HTMLElement>(null);
  const listRef = useRef<HTMLUListElement>(null);
  const lineRef = useRef<HTMLSpanElement>(null);
  const overlayRef = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);
  const [inLayers, setInLayers] = useState(false);

  const active = pathname.startsWith("/research") ? "research" : pathname.startsWith("/playground") ? "playground" : pathname === "/" && inLayers ? "layers" : null;

  // entrance: slides down 12px and fades in (part of the hero beat on the landing page)
  useEffect(() => {
    const nav = navRef.current; if (!nav) return;
    if (prefersReducedMotion()) { motion.set(nav, { opacity: 1 }); return; }
    const t = motion.fromTo(nav, { opacity: 0, y: -12 }, { opacity: 1, y: 0, duration: dur.base, delay: 0.12, ease: ease.out });
    return () => { t.kill(); };
  }, []);

  // which section is in view (home only)
  useEffect(() => {
    if (pathname !== "/") { setInLayers(false); return; }
    const el = document.getElementById("layers");
    if (!el) return;
    const io = new IntersectionObserver(([e]) => setInLayers(e.isIntersecting), { rootMargin: "-40% 0px -40% 0px" });
    io.observe(el);
    return () => io.disconnect();
  }, [pathname]);

  // sliding underline
  useEffect(() => {
    const list = listRef.current, line = lineRef.current;
    if (!list || !line) return;
    const el = active ? list.querySelector<HTMLElement>(`[data-key="${active}"]`) : null;
    if (!el) { motion.to(line, { opacity: 0, duration: dur.short }); return; }
    const to = { x: el.offsetLeft + 12, width: el.offsetWidth - 24, opacity: 1 };
    if (prefersReducedMotion()) motion.set(line, to); else motion.to(line, { ...to, duration: dur.short, ease: ease.out });
  }, [active]);

  // hide on scroll down, return on scroll up
  useEffect(() => {
    const nav = navRef.current; if (!nav) return;
    const st = ScrollTrigger.create({
      start: 0, end: "max",
      onUpdate: (self) => {
        if (open) return;
        const hide = self.direction === 1 && self.scroll() > 140;
        motion.to(nav, { yPercent: hide ? -160 : 0, duration: dur.short, ease: ease.out, overwrite: "auto" });
      },
    });
    return () => st.kill();
  }, [open]);

  // mobile overlay: staggered link reveal, scroll lock, escape to close
  useEffect(() => {
    const ov = overlayRef.current; if (!ov) return;
    if (open) {
      document.body.style.overflow = "hidden";
      motion.fromTo(ov.querySelectorAll("[data-ov]"), { opacity: 0, y: 16 }, { opacity: 1, y: 0, duration: dur.base, stagger: 0.06, ease: ease.out, delay: 0.05 });
      const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") setOpen(false); };
      window.addEventListener("keydown", onKey);
      return () => { document.body.style.overflow = ""; window.removeEventListener("keydown", onKey); };
    }
    document.body.style.overflow = "";
  }, [open]);
  useEffect(() => setOpen(false), [pathname]);

  return (
    <>
      <header ref={navRef} data-nav data-reveal className="fixed left-1/2 top-4 w-[calc(100%-2rem)] max-w-fit -translate-x-1/2" style={{ zIndex: 30 }}>
        <nav aria-label="Primary" className="glass flex h-14 items-center gap-2 rounded-full border border-line pl-5 pr-2 md:gap-6">
          <Link href={ROUTES.home} aria-label="DIDA, home" className="rounded-full"><Wordmark /></Link>
          <ul ref={listRef} className="relative ml-4 hidden items-center md:flex">
            {LINKS.map((l) => (
              <li key={l.key}>
                <Link href={l.href} data-key={l.key} aria-current={active === l.key ? "page" : undefined}
                  className={clsx("block rounded-full px-3 py-2 text-sm transition-colors", active === l.key ? "text-bone" : "text-bone-2 hover:text-bone")}>{l.label}</Link>
              </li>
            ))}
            <li><a href={GITHUB_URL} target="_blank" rel="noreferrer" className="block rounded-full px-3 py-2 text-sm text-bone-2 transition-colors hover:text-bone">GitHub</a></li>
            <span ref={lineRef} aria-hidden className="pointer-events-none absolute bottom-1 left-0 h-px bg-line-strong" style={{ opacity: 0, width: 0, background: "var(--bone-2)" }} />
          </ul>
          <div className="ml-auto hidden md:block"><MagneticLink href={ROUTES.console} size="sm">Open console</MagneticLink></div>
          <button className="ml-auto grid size-10 place-items-center rounded-full text-bone hover:bg-ink-3 md:hidden" aria-label={open ? "Close menu" : "Open menu"} aria-expanded={open} aria-controls="mobile-menu" onClick={() => setOpen((v) => !v)}>
            {open ? <X size={20} /> : <List size={20} />}
          </button>
        </nav>
      </header>
      <div ref={overlayRef} id="mobile-menu" hidden={!open} className="fixed inset-0 flex flex-col justify-center gap-2 bg-ink-0 px-8 md:hidden" style={{ zIndex: 40 }}>
        {LINKS.map((l) => <Link key={l.key} data-ov href={l.href} onClick={() => setOpen(false)} className="py-3 text-4xl font-semibold tracking-tight text-bone">{l.label}</Link>)}
        <a data-ov href={GITHUB_URL} target="_blank" rel="noreferrer" className="py-3 text-4xl font-semibold tracking-tight text-bone-2">GitHub</a>
        <div data-ov className="mt-6"><MagneticLink href={ROUTES.console}>Open console</MagneticLink></div>
      </div>
    </>
  );
}
