import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const api = process.env.PARLEY_API_URL ?? "http://localhost:8787";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: api, ws: true },
    },
  },
});
