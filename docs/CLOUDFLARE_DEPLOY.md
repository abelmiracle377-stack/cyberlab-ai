# Deploying CyberLab AI to Cloudflare

CyberLab uses Next.js with **Node.js-runtime** API routes (for example the
Paystack webhook uses `node:crypto`). The right adapter for Cloudflare is
**OpenNext for Cloudflare** (`@opennextjs/cloudflare`), which runs on Cloudflare
Workers with the `nodejs_compat` flag. (The older `@cloudflare/next-on-pages`
requires every route to use the Edge runtime and is **not** suitable here.)

Config is already in the repo: `wrangler.jsonc` and `open-next.config.ts`.

## 1. Install the adapter

```bash
npm i -D @opennextjs/cloudflare wrangler
```

## 2. Build and deploy

```bash
npx opennextjs-cloudflare build
npx opennextjs-cloudflare deploy      # or: npx wrangler deploy
```

For local preview: `npx opennextjs-cloudflare preview`.

Or connect the GitHub repo in the Cloudflare dashboard (Workers & Pages → Create →
Workers) with build command `npx opennextjs-cloudflare build` and deploy command
`npx wrangler deploy`.

## 3. Secrets / environment variables

Set these in the Cloudflare dashboard (Settings → Variables) or via
`wrangler secret put <NAME>`:

- `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY` — public (plain vars).
- `SUPABASE_SERVICE_ROLE_KEY` — secret.
- `OPENROUTER_API_KEY` — secret.
- `PAYSTACK_SECRET_KEY`, `PAYSTACK_PLAN_CODE` — secret.
- `CYBERLAB_UNCENSORED_BASE_URL` / `_API_KEY` / `_MODELS` / `_ALLOW_KEYLESS` /
  `_COMPLETIONS_PATH` — optional, secret.
- `CYBERLAB_MCP_API_KEY` — optional, secret.

`NEXT_PUBLIC_*` values are inlined at build time, so set them before building.

## 4. Post-deploy wiring

- **Supabase Auth** → set the Site URL and the redirect to
  `https://<your-domain>/auth/callback`.
- **Paystack webhook** → `https://<your-domain>/api/paystack/webhook`.
- **Companion bridge** is unchanged — it runs on the operator's own machine
  (`127.0.0.1:8765`); the browser talks to it directly, not through Cloudflare.

## Notes & compatibility

- `nodejs_compat` (set in `wrangler.jsonc`) provides `node:crypto`, `Buffer`,
  streams, etc. used by the billing and gateway routes.
- `export const maxDuration` on some routes is a Vercel hint and is simply
  ignored on Workers (no change needed). Worker CPU limits apply instead; the
  long-running AI routes already cap work and use `AbortSignal.timeout`.
- Response streaming (the AI agent) works on Workers.
- The security headers in `next.config.ts` are emitted by the adapter.
- Keep `vercel.json` only if you also deploy to Vercel; Cloudflare ignores it.
