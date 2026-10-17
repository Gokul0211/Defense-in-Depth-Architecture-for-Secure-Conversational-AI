import type { Metadata } from "next";
import { Console } from "@/components/console/Console";
export const metadata: Metadata = { title: "Console" };
export default function ConsolePage() { return <Console />; }
