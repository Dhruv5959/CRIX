import { forwardRef, type InputHTMLAttributes, type SelectHTMLAttributes, type TextareaHTMLAttributes } from "react";
import { cn } from "@/lib/utils";

// Frosted field: translucent fill over whatever is behind it, with a matching
// blur so it reads as cut from the same glass as the card it sits in.
const field =
  "w-full rounded-xl border border-white/15 bg-white/[0.06] text-sm text-ink placeholder:text-ink-faint backdrop-blur-md " +
  "transition-[border-color,box-shadow,background-color] duration-150 " +
  "focus:border-accent/60 focus:bg-white/[0.09] focus:outline-none focus:ring-2 focus:ring-accent/25";

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => (
    <input ref={ref} className={cn("h-10 px-3", field, className)} {...props} />
  ),
);
Input.displayName = "Input";

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaHTMLAttributes<HTMLTextAreaElement>>(
  ({ className, ...props }, ref) => (
    <textarea ref={ref} className={cn("px-3 py-2", field, className)} {...props} />
  ),
);
Textarea.displayName = "Textarea";

export const Select = forwardRef<HTMLSelectElement, SelectHTMLAttributes<HTMLSelectElement>>(
  ({ className, children, ...props }, ref) => (
    // [color-scheme:light] applies to the OS-rendered option POPUP (Windows/
    // Chromium paints it dark when the page is dark), while author classes
    // keep the closed control's glass look. White list, black text.
    <select
      ref={ref}
      className={cn("h-10 cursor-pointer px-3 [color-scheme:light]", field, className)}
      {...props}
    >
      {children}
    </select>
  ),
);
Select.displayName = "Select";

export function Label({ children, className }: { children: React.ReactNode; className?: string }) {
  return <label className={cn("mb-1.5 block text-xs font-medium text-ink-muted", className)}>{children}</label>;
}