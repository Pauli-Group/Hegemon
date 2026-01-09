import type { Config } from "tailwindcss";

/**
 * Hegemon Brand Tokens
 * See BRAND.md for full color system documentation
 */
const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        // Primary base - Deep Midnight
        midnight: "#0E1C36",
        // Accent - Ionosphere (links, focus states, actionable elements)
        ionosphere: "#1BE7FF",
        // Secondary highlight - Molten Amber (alerts, badges)
        amber: "#F5A623",
        // Positive state - Proof Green (success, upward trends)
        "proof-green": "#19B37E",
        // Negative state - Guard Rail (errors, warnings)
        "guard-rail": "#FF4E4E",
        // Neutral surfaces
        "neutral-light": "#F4F7FB",
        "neutral-mid": "#E1E6EE",
        // Legacy aliases
        background: "var(--background)",
        foreground: "var(--foreground)",
      },
      fontFamily: {
        sans: ["var(--font-space-grotesk)", "Inter", "sans-serif"],
        mono: ["var(--font-jetbrains-mono)", "monospace"],
      },
      spacing: {
        // 8px base grid per BRAND.md
        "18": "4.5rem",
        "22": "5.5rem",
      },
    },
  },
  plugins: [],
};
export default config;
