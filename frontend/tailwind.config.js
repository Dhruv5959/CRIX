/** @type {import('tailwindcss').Config} */
export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Glassmorphism needs a *vibrant* backdrop for the frost to read against
        // (ui-ux-pro-max: style=glassmorphism, "vibrant background, light source,
        // layered depth"). base-950 is the dark room; the colour lives in the
        // fixed body gradients in index.css. One accent (cyan) is still the only
        // brand hue — emerald/amber/rose/sky/violet stay reserved for provenance
        // and severity, so status colour is never decorative.
        base: {
          950: "#050912",
          900: "#0a1020",
          850: "#0f1830",
          800: "#16233f",
          700: "#1f3057",
          600: "#2b4173",
        },
        ink: {
          DEFAULT: "#eaf1fb",
          muted: "#a8b8d2",
          // Lightened from #78899f. Measured: the old value failed WCAG AA on
          // the small (10–12px) secondary text that carries the provenance and
          // unit detail — the worst case measured 2.46:1.
          faint: "#8395ac",
        },
        accent: {
          DEFAULT: "#22d3ee",
          soft: "#0891b2",
          glow: "#67e8f9",
        },
      },
      fontFamily: {
        // Fira Sans / Fira Code — the pairing ui-ux-pro-max returns for
        // "dashboard, data, analytics, technical, precise". Fira Code keeps
        // every number/ID/hash column-aligned (it is monospaced by design).
        sans: ["'Fira Sans'", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["'Fira Code'", "ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
      fontSize: {
        "2xl": ["1.5rem", { lineHeight: "2rem", letterSpacing: "-0.01em" }],
        "3xl": ["1.875rem", { lineHeight: "2.25rem", letterSpacing: "-0.015em" }],
      },
      boxShadow: {
        // Frosted panel: a soft cast shadow for Z-depth plus a 1px inner top
        // highlight that reads as the glass edge catching the light source.
        glass:
          "0 10px 34px -12px rgba(2,6,23,0.80), inset 0 1px 0 0 rgba(255,255,255,0.10)",
        "glass-hover":
          "0 18px 48px -14px rgba(2,6,23,0.90), inset 0 1px 0 0 rgba(255,255,255,0.16)",
        panel:
          "0 10px 34px -12px rgba(2,6,23,0.80), inset 0 1px 0 0 rgba(255,255,255,0.10)",
        "panel-hover":
          "0 18px 48px -14px rgba(2,6,23,0.90), inset 0 1px 0 0 rgba(255,255,255,0.16)",
        accent:
          "0 0 0 1px rgba(34,211,238,0.35), 0 10px 34px -12px rgba(34,211,238,0.45)",
        inset: "inset 0 1px 0 0 rgba(255,255,255,0.06)",
      },
      borderRadius: {
        xl: "0.875rem",
        "2xl": "1.25rem",
        "3xl": "1.75rem",
      },
      keyframes: {
        "fade-in": {
          "0%": { opacity: "0", transform: "translateY(4px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        shimmer: {
          "0%": { backgroundPosition: "-200% 0" },
          "100%": { backgroundPosition: "200% 0" },
        },
        "pulse-soft": {
          "0%, 100%": { opacity: "1" },
          "50%": { opacity: "0.55" },
        },
      },
      animation: {
        "fade-in": "fade-in 0.3s ease-out",
        shimmer: "shimmer 1.6s ease-in-out infinite",
        "pulse-soft": "pulse-soft 2s ease-in-out infinite",
      },
    },
  },
  plugins: [],
};