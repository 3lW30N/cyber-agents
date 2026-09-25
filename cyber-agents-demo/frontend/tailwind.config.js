/** @type {import('tailwindcss').Config} */
export default {
  content: [
    './index.html',
    './src/**/*.{js,ts,jsx,tsx}',
  ],
  theme: {
    extend: {
      colors: {
        'cyber-red': '#ef4444',
        'cyber-blue': '#3b82f6',
        'cyber-green': '#22c55e',
        'cyber-yellow': '#eab308',
        'bg-dark': '#0a0e1a',
        'bg-panel': '#111827',
      },
    },
  },
  plugins: [],
}
