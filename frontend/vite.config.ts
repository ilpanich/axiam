import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    proxy: {
      "/api": "http://localhost:8080",
      "/auth": "http://localhost:8080",
      // Use regex to match /oauth2/ and /oauth2? but NOT /oauth2-clients (frontend route)
      "^/oauth2(/|\\?|$)": {
        target: "http://localhost:8080",
        rewrite: (path) => path,
      },
    },
  },
});
