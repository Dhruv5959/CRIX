import { cn } from "@/lib/utils";

export function Switch({
  checked,
  onChange,
  label,
  description,
  disabled,
}: {
  checked: boolean;
  onChange: (next: boolean) => void;
  label?: string;
  description?: string;
  disabled?: boolean;
}) {
  return (
    <label className={cn("flex cursor-pointer items-start gap-3", disabled && "cursor-not-allowed opacity-50")}>
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        disabled={disabled}
        onClick={() => onChange(!checked)}
        className={cn(
          "relative mt-0.5 h-5 w-9 shrink-0 cursor-pointer rounded-full border transition-colors",
          "focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/60 focus-visible:ring-offset-2 focus-visible:ring-offset-base-950",
          "disabled:cursor-not-allowed",
          checked ? "border-accent/60 bg-accent/30" : "border-white/15 bg-white/[0.06]",
        )}
      >
        <span
          className={cn(
            "absolute top-0.5 h-3.5 w-3.5 rounded-full transition-all",
            checked ? "left-4 bg-accent" : "left-0.5 bg-ink-faint",
          )}
        />
      </button>
      {(label || description) && (
        <span className="text-sm">
          {label && <span className="block text-ink">{label}</span>}
          {description && <span className="block text-xs text-ink-faint">{description}</span>}
        </span>
      )}
    </label>
  );
}