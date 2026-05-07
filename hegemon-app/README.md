# hegemon-app

Electron desktop app for Hegemon: node control + shielded wallet UI.

## Required binaries

The app spawns two Rust binaries from the workspace's `target/release/` directory at runtime:

- `hegemon-node` — the Substrate-based chain node
- `walletd` — the wallet daemon (created/opened on first wallet action)

Both must be built from the **repo root** before launching the app. The Electron resolver (`electron/binPaths.ts`) walks up from this directory looking for them.

## First-run setup

From the repo root:

```bash
make setup       # toolchains, one-time
make app         # builds hegemon-node + walletd
cd hegemon-app
npm install
npm run dev
```

For an interactive walk-through that detects existing state and only builds what's missing, run `/hegemon-setup` in Claude Code or ask "help me set up the repo".

## Override binary location

Set `HEGEMON_BIN_DIR` to point the resolver at a custom directory (debug builds, release artifacts from CI, etc.):

```bash
HEGEMON_BIN_DIR=/path/to/bins npm run dev
```
