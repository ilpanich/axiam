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
