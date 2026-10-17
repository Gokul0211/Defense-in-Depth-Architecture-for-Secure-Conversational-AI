"use client";
import { usePathname } from "next/navigation";
import { Nav } from "./Nav";
import { SmoothScroll } from "./SmoothScroll";
import { PageTransition } from "./PageTransition";
import { BackgroundFieldLazy } from "@/components/three/lazy";

/** Global chrome. The console is a dense tool: no floating nav, no background shader. */
export function Chrome() {
  const pathname = usePathname();
  const tool = pathname.startsWith("/console");
  return (
    <>
      <SmoothScroll />
      <PageTransition />
      {!tool && <BackgroundFieldLazy />}
      {!tool && <Nav />}
    </>
  );
}
