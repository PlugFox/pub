import solid from "@astrojs/solid-js";
import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "astro/config";

// SSG by default (decision 14): landing/docs prerendered, the app island is
// client:only. The 10 locales come from decision 08; English stays unprefixed.
export default defineConfig({
  integrations: [solid()],
  vite: {
    plugins: [tailwindcss()],
    build: {
      // Never inline small bundled scripts into the HTML: the anti-FOUC theme
      // script in the base layout must stay the ONLY inline script (strict CSP
      // with a nonce/hash for exactly that one — decisions 03/14).
      assetsInlineLimit: 0,
    },
  },
  i18n: {
    defaultLocale: "en",
    locales: ["en", "ru", "fr", "it", "de", "es", "pt", "ja", "ko", "zh-Hans"],
    routing: {
      prefixDefaultLocale: false,
    },
  },
});
