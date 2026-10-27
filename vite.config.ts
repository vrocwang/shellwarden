import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Tauri 需要一个固定端口：devUrl 写死为 127.0.0.1:5173。
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true
  },
  build: {
    target: "safari15",
    outDir: "dist",
    emptyOutDir: true
  }
});
