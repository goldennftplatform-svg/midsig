import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";

export default defineConfig({
  base: "./",
  define: { "process.env.NODE_ENV": JSON.stringify("production") },
  build: {
    outDir: fileURLToPath(new URL("../docs/privy", import.meta.url)),
    emptyOutDir: true,
    sourcemap: false,
    lib: {
      entry: fileURLToPath(new URL("./src/privy-entry.tsx", import.meta.url)),
      formats: ["es"],
      fileName: () => "privy-entry.js",
    },
  },
});
