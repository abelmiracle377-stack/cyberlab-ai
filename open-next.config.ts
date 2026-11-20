// @ts-nocheck
// OpenNext Cloudflare adapter config. The dependency is installed at deploy time
// (not part of the Next build), so type-checking is disabled for this file.
// Install with:  npm i -D @opennextjs/cloudflare wrangler
// Build & deploy: npx opennextjs-cloudflare build && npx opennextjs-cloudflare deploy
// See docs/CLOUDFLARE_DEPLOY.md.
import { defineCloudflareConfig } from "@opennextjs/cloudflare";

export default defineCloudflareConfig({
  // Default (no R2 cache) is fine for CyberLab. Add an incrementalCache only if
  // you enable ISR/revalidation later.
});
