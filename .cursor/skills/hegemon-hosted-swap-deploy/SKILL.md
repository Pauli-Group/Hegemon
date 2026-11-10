---
name: hegemon-hosted-swap-deploy
description: >-
  Deploys the Hegemon testnet swap Worker hegemon-swap-testnet and its D1
  database without an interactive Cloudflare login. Use when updating the
  hosted testnet site, deploying the Cloudflare Worker, running Wrangler,
  backing up or migrating D1, or when the user mentions hegemon-swap-testnet,
  willdoyle422.workers.dev, wrangler deploy, or the hosted swap board.
---

# Hosted swap deploy

The live site is https://hegemon-swap-testnet.willdoyle422.workers.dev. Config is `swap-service/cloudflare/wrangler.jsonc`. D1 database name `hegemon-swap-testnet`, id `bc34dcb0-7983-4413-98c9-a08ba6dce311`. Work from the repository root with Node 24 (`node` on this machine is already 24).

The deploy order in `swap-service/README.md` is the procedure. This skill only adds the authorization rule that README assumes.

## Authorization

Do not run `wrangler login`. Do not open a browser. Do not ask the user to sign in. The original deploy did not do that: Wrangler was already authorized, and `whoami` was the check.

Find a session in this order. Never print, copy, or commit a token, and never read or change a `.wrangler` directory.

1. If `/workspace/chain-tools/cloudflare-cli/node_modules/wrangler/bin/wrangler.js` exists, that is the binary that deployed this Worker. Use it for every Wrangler command below instead of `npx wrangler@4`.
2. Otherwise, if `CLOUDFLARE_API_TOKEN` is already in the environment, use `npx wrangler@4`. Do not print the variable.
3. Otherwise, if `$HOME/.config/.wrangler/config/default.toml` or `$HOME/.wrangler/config/default.toml` exists, use `npx wrangler@4`. Wrangler reads that file. Do not open it.
4. Otherwise stop. This home PC has none of those. The session that deployed the site lived on the `/workspace` host (repo root `/workspace/Hegemon`). Codex hosts that show up on Tailscale from here do not accept SSH. Report that the site was not updated.

Confirm with whoami and keep the output to the account name:

```bash
npx wrangler@4 whoami --config swap-service/cloudflare/wrangler.jsonc
```

`You are not authenticated` means stop. A missing session is not a reason to start OAuth.

## Deploy

Run these in order. A failing step stops the rest.

1. `node scripts/build_client_manifest.mjs --check`
2. `make swap-test` (the fast tier). Run `make swap-integration` when the change touches the hosted page or Worker. Do not start `make swap-hegemon-local` for a site deploy.
3. Back up remote D1 outside the repo, then do not commit that file:

```bash
mkdir -p "$HOME/.hegemon-d1-backups"
npx wrangler@4 d1 export hegemon-swap-testnet --remote \
  --output "$HOME/.hegemon-d1-backups/d1-backup-$(date +%F).sql" \
  --config swap-service/cloudflare/wrangler.jsonc
```

4. See whether the identity columns exist:

```bash
npx wrangler@4 d1 execute hegemon-swap-testnet --remote \
  --command "PRAGMA table_info(offers)" \
  --config swap-service/cloudflare/wrangler.jsonc
```

Apply `swap-service/cloudflare/migrations/0002_identity.sql` with `d1 execute --file` only when `owner_identity` is absent. It is two `ADD COLUMN` statements and deletes nothing. Deploying the Worker before this migration makes reservations fail.

5. `npx wrangler@4 deploy --config swap-service/cloudflare/wrangler.jsonc`
6. `node scripts/verify_hosted_client.mjs --base https://hegemon-swap-testnet.willdoyle422.workers.dev`

Then confirm the live page contains `Guided swap` and that `/guided.mjs`, `/identity.mjs`, and `/client-manifest.json` return 200.

The hosted page still cannot spend Hegemon. That leg stays on `scripts/local_swap_companion.py --hegemon-public` because the page's `connect-src` is `'self'`.
