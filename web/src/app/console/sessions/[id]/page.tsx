import type { Metadata } from "next";
import { SessionForensics } from "@/components/console/SessionForensics";
export const metadata: Metadata = { title: "Session" };
export default async function SessionPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return <SessionForensics id={decodeURIComponent(id)} />;
}
