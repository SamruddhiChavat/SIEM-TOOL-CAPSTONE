import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
  ],
  resolve: {
    dedupe: ['react', 'react-dom', 'react/jsx-runtime'],
  },
  server: {
    port: 5174,
    proxy: {
      '/api/sandbox': {
        target: 'http://localhost:8000', // Python backend
        changeOrigin: true,
      },
      '/api': {
        target: 'http://localhost:4000', // relay server (dev)
        changeOrigin: true,
        ws: true,
      }
    }
  }
})


