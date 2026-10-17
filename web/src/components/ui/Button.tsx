import Link from "next/link";
import { forwardRef, type ButtonHTMLAttributes, type ReactNode } from "react";
import { ArrowRight } from "@phosphor-icons/react/dist/ssr";
import clsx from "clsx";

type Variant = "primary" | "secondary" | "ghost" | "link";
type Size = "sm" | "md";

const base = "inline-flex items-center justify-center gap-2 font-medium whitespace-nowrap select-none transition-[background-color,color,border-color,transform] duration-[160ms] ease-[var(--ease-out)] active:scale-[0.98] disabled:opacity-40 disabled:pointer-events-none";
const variants: Record<Variant, string> = {
  primary: "rounded-full bg-signal text-ink-0 hover:bg-[#ff6a40]",
  secondary: "rounded-full border border-line-strong text-bone hover:bg-ink-3",
  ghost: "rounded-full text-bone-2 hover:text-bone hover:bg-ink-2",
  link: "link-arrow text-bone hover:text-signal",
};
const sizes: Record<Size, string> = { sm: "h-9 px-4 text-sm", md: "h-12 px-6 text-[0.95rem]" };

type Common = { variant?: Variant; size?: Size; className?: string; children: ReactNode; arrow?: boolean };

export const Button = forwardRef<HTMLButtonElement, Common & ButtonHTMLAttributes<HTMLButtonElement>>(
  function Button({ variant = "primary", size = "md", className, children, arrow, ...rest }, ref) {
    return (
      <button ref={ref} className={clsx(base, variants[variant], variant !== "link" && sizes[size], className)} {...rest}>
        {children}{arrow && <ArrowRight size={16} weight="regular" aria-hidden />}
      </button>
    );
  },
);

export const ButtonLink = forwardRef<HTMLAnchorElement, Common & { href: string; external?: boolean }>(
  function ButtonLink({ variant = "primary", size = "md", className, children, href, external, arrow }, ref) {
    const cls = clsx(base, variants[variant], variant !== "link" && sizes[size], className);
    const inner = <>{children}{arrow && <ArrowRight size={16} weight="regular" aria-hidden />}</>;
    return external
      ? <a ref={ref} href={href} className={cls} target="_blank" rel="noreferrer">{inner}</a>
      : <Link ref={ref} href={href} className={cls}>{inner}</Link>;
  },
);
