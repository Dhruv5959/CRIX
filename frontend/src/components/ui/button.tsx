import { forwardRef, type ButtonHTMLAttributes } from "react";
import { cn } from "@/lib/utils";

type Variant = "primary" | "secondary" | "ghost" | "danger";
type Size = "sm" | "md" | "lg";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
}

const variants: Record<Variant, string> = {
  primary:
    "border border-white/20 bg-gradient-to-b from-accent to-accent-soft text-base-950 font-semibold shadow-accent hover:from-accent-glow hover:to-accent disabled:opacity-40",
  secondary:
    "border border-white/15 bg-white/[0.08] text-ink backdrop-blur-md hover:bg-white/[0.14] disabled:opacity-40",
  ghost: "text-ink-muted backdrop-blur-md hover:bg-white/10 hover:text-ink disabled:opacity-40",
  danger:
    "border border-rose-400/30 bg-rose-500/15 text-rose-200 backdrop-blur-md hover:bg-rose-500/25",
};

const sizes: Record<Size, string> = {
  sm: "h-8 px-3 text-xs rounded-lg",
  md: "h-10 px-4 text-sm rounded-xl",
  lg: "h-11 px-5 text-sm rounded-xl",
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = "secondary", size = "md", ...props }, ref) => (
    <button
      ref={ref}
      className={cn(
        // cursor-pointer is explicit: Tailwind preflight does not guarantee it on
        // <button>, and a "clickable but no pointer" control reads as broken.
        "inline-flex cursor-pointer items-center justify-center gap-2 whitespace-nowrap",
        "transition-[background-color,border-color,color,transform,box-shadow] duration-150",
        "active:translate-y-px",
        "focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/60 focus-visible:ring-offset-2 focus-visible:ring-offset-base-950",
        "disabled:cursor-not-allowed disabled:active:translate-y-0",
        variants[variant],
        sizes[size],
        className,
      )}
      {...props}
    />
  ),
);
Button.displayName = "Button";