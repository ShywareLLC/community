import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["**/*.test.js", "**/*.spec.js", "**/*.test.mjs", "**/*.spec.mjs"],
    environment: "jsdom",
    globals: true,
    setupFiles: []
  }
});
