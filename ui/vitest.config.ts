import { defineConfig } from "vitest/config";
export default defineConfig({
  // The tests also read the legacy page's adapter (../src/management.js).
  server: { fs: { allow: [".."] } },
  test: {
    environment: "jsdom",
    setupFiles: ["./tests/setup.ts"],
    restoreMocks: true,
  },
});
