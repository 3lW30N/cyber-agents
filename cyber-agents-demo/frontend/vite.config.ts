import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// NODE_API_URL is set in docker-compose for the proxy target (server-side only).
// VITE_API_URL is only set at production build time for the browser client.
const BACKEND = process.env.NODE_API_URL ?? process.env.VITE_API_URL ?? 'http://localhost:8000'

export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 5173,
    watch: {
      usePolling: true,
      interval: 1000,
    },
    proxy: {
      '/simulation': { target: BACKEND, changeOrigin: true },
      '/config':     { target: BACKEND, changeOrigin: true },
      '/events':     { target: BACKEND, changeOrigin: true, ws: false },
      '/agents':     { target: BACKEND, changeOrigin: true },
      '/network':    { target: BACKEND, changeOrigin: true },
      '/ws':         { target: BACKEND.replace('http', 'ws'), changeOrigin: true, ws: true },
      '/health':     { target: BACKEND, changeOrigin: true },
    },
  },
})
