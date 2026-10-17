import type { Metadata, Viewport } from "next";
import { GeistSans } from "geist/font/sans";
import { GeistMono } from "geist/font/mono";
import { Chrome } from "@/components/sections/Chrome";
import "@/styles/globals.css";

export const metadata: Metadata = {
  title: { default: "DIDA: Defense-in-Depth Architecture for secure conversational AI", template: "%s | DIDA" },
  description: "DIDA screens every prompt, document, tool call and reply for LLM apps, and measures what layered defenses actually catch.",
  icons: { icon: "/favicon.svg" },
};
export const viewport: Viewport = { themeColor: "#0b0b0c", colorScheme: "dark" };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${GeistSans.variable} ${GeistMono.variable}`}>
      <body>
        <noscript><style>{`[data-reveal],[data-reveal-children]>*{opacity:1!important}`}</style></noscript>
        <a href="#main" className="skip-link">Skip to content</a>
        <Chrome />
        <div className="grain" aria-hidden="true" />
        <div className="relative" style={{ zIndex: 10 }}>{children}</div>
      </body>
    </html>
  );
}
