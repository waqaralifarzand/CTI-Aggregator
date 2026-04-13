/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        dark: {
          bg: "#0f172a",
          card: "#1e293b",
          border: "#334155",
          text: "#e2e8f0",
          muted: "#94a3b8",
        },
        severity: {
          critical: "#ef4444",
          high: "#f97316",
          medium: "#eab308",
          low: "#22c55e",
        },
      },
    },
  },
  plugins: [],
};
