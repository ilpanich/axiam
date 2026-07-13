/** @type {import('tailwindcss').Config} */
export default {
  darkMode: ["class"],
  content: [
    "./index.html",
    "./src/**/*.{ts,tsx}",
  ],
  theme: {
    container: {
      center: true,
      padding: "2rem",
      screens: {
        "2xl": "1400px",
      },
    },
    extend: {
      colors: {
        // Pin the stock Tailwind palette families used by the UI to their
        // Tailwind v3 values. Tailwind v4 ships a redesigned (more vivid, P3)
        // default palette; without this the status badges / semantic colors
        // would shift on upgrade. This preserves the exact rendered colors.
        red: {
          50: "#fef2f2", 100: "#fee2e2", 200: "#fecaca", 300: "#fca5a5",
          400: "#f87171", 500: "#ef4444", 600: "#dc2626", 700: "#b91c1c",
          800: "#991b1b", 900: "#7f1d1d", 950: "#450a0a",
        },
        orange: {
          50: "#fff7ed", 100: "#ffedd5", 200: "#fed7aa", 300: "#fdba74",
          400: "#fb923c", 500: "#f97316", 600: "#ea580c", 700: "#c2410c",
          800: "#9a3412", 900: "#7c2d12", 950: "#431407",
        },
        amber: {
          50: "#fffbeb", 100: "#fef3c7", 200: "#fde68a", 300: "#fcd34d",
          400: "#fbbf24", 500: "#f59e0b", 600: "#d97706", 700: "#b45309",
          800: "#92400e", 900: "#78350f", 950: "#451a03",
        },
        emerald: {
          50: "#ecfdf5", 100: "#d1fae5", 200: "#a7f3d0", 300: "#6ee7b7",
          400: "#34d399", 500: "#10b981", 600: "#059669", 700: "#047857",
          800: "#065f46", 900: "#064e3b", 950: "#022c22",
        },
        cyan: {
          50: "#ecfeff", 100: "#cffafe", 200: "#a5f3fc", 300: "#67e8f9",
          400: "#22d3ee", 500: "#06b6d4", 600: "#0891b2", 700: "#0e7490",
          800: "#155e75", 900: "#164e63", 950: "#083344",
        },
        blue: {
          50: "#eff6ff", 100: "#dbeafe", 200: "#bfdbfe", 300: "#93c5fd",
          400: "#60a5fa", 500: "#3b82f6", 600: "#2563eb", 700: "#1d4ed8",
          800: "#1e40af", 900: "#1e3a8a", 950: "#172554",
        },
        purple: {
          50: "#faf5ff", 100: "#f3e8ff", 200: "#e9d5ff", 300: "#d8b4fe",
          400: "#c084fc", 500: "#a855f7", 600: "#9333ea", 700: "#7e22ce",
          800: "#6b21a8", 900: "#581c87", 950: "#3b0764",
        },
        pink: {
          50: "#fdf2f8", 100: "#fce7f3", 200: "#fbcfe8", 300: "#f9a8d4",
          400: "#f472b6", 500: "#ec4899", 600: "#db2777", 700: "#be185d",
          800: "#9d174d", 900: "#831843", 950: "#500724",
        },
        rose: {
          50: "#fff1f2", 100: "#ffe4e6", 200: "#fecdd3", 300: "#fda4af",
          400: "#fb7185", 500: "#f43f5e", 600: "#e11d48", 700: "#be123c",
          800: "#9f1239", 900: "#881337", 950: "#4c0519",
        },
        background: "#0d0d2b",
        foreground: "#f8fafc",
        surface: "rgba(255,255,255,0.05)",
        border: "rgba(0,212,255,0.15)",
        primary: {
          DEFAULT: "#00d4ff",
          foreground: "#0d0d2b",
        },
        accent: {
          DEFAULT: "#a855f7",
          foreground: "#f8fafc",
        },
        muted: {
          DEFAULT: "#1e1b4b",
          foreground: "#94a3b8",
        },
        destructive: {
          DEFAULT: "#ef4444",
          foreground: "#f8fafc",
        },
        warning: {
          DEFAULT: "#f59e0b",
          foreground: "#0d0d2b",
        },
        card: {
          DEFAULT: "rgba(255,255,255,0.05)",
          foreground: "#f8fafc",
        },
        popover: {
          DEFAULT: "#13123a",
          foreground: "#f8fafc",
        },
        secondary: {
          DEFAULT: "#1e1b4b",
          foreground: "#f8fafc",
        },
        input: "rgba(0,212,255,0.15)",
        ring: "#00d4ff",
      },
      borderRadius: {
        lg: "0.75rem",
        md: "0.5rem",
        sm: "0.375rem",
      },
      backgroundImage: {
        "axiam-gradient": "linear-gradient(135deg, #0d0d2b 0%, #1a0a3d 100%)",
      },
      boxShadow: {
        "glow-cyan": "0 0 12px rgba(0,212,255,0.4)",
        "glow-cyan-lg": "0 0 24px rgba(0,212,255,0.3)",
        "glow-purple": "0 0 12px rgba(168,85,247,0.4)",
        glass: "0 8px 32px rgba(0,0,0,0.4)",
      },
      keyframes: {
        "accordion-down": {
          from: { height: "0" },
          to: { height: "var(--radix-accordion-content-height)" },
        },
        "accordion-up": {
          from: { height: "var(--radix-accordion-content-height)" },
          to: { height: "0" },
        },
        "neon-pulse": {
          "0%, 100%": {
            opacity: "1",
            boxShadow: "0 0 20px rgba(0,212,255,0.6)",
          },
          "50%": {
            opacity: "0.8",
            boxShadow: "0 0 40px rgba(0,212,255,0.3)",
          },
        },
        "ring-spin": {
          from: { transform: "rotate(0deg)" },
          to: { transform: "rotate(360deg)" },
        },
        "ring-spin-reverse": {
          from: { transform: "rotate(360deg)" },
          to: { transform: "rotate(0deg)" },
        },
      },
      animation: {
        "accordion-down": "accordion-down 0.2s ease-out",
        "accordion-up": "accordion-up 0.2s ease-out",
        "neon-pulse": "neon-pulse 2s ease-in-out infinite",
        "ring-spin": "ring-spin 8s linear infinite",
        "ring-spin-reverse": "ring-spin-reverse 12s linear infinite",
      },
    },
  },
  plugins: [],
};
