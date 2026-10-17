"use client";
import dynamic from "next/dynamic";
import { LabyrinthMark } from "@/components/brand/LabyrinthMark";

/** three + scene chunks load after hydration (ssr: false); the static mark holds the slot meanwhile. */
export const LabyrinthCanvasLazy = dynamic(() => import("./LabyrinthCanvas"), {
  ssr: false,
  loading: () => <div className="absolute inset-0 grid place-items-center"><LabyrinthMark className="h-[72%] w-[72%]" decorative /></div>,
});
export const BackgroundFieldLazy = dynamic(() => import("./BackgroundField"), { ssr: false });
