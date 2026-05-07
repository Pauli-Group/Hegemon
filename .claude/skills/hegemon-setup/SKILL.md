---
name: hegemon-setup
description: Interactive first-run setup for a fresh Hegemon clone. Detects existing state, asks the user what they want to set up (CLI node, Electron desktop app, or full contributor flow), then orchestrates `make setup`, `make node`, `make walletd`, `npm install`, and `make check` in the right order with verification at each step. Use when the user clones the repo and asks to set it up, says "help me set up", "set up the repo", "first time", "fresh clone", or runs /hegemon-setup.
metadata:
  repo: Reflexivity/Hegemon
  version: "1.0"
---

# Goal

Walk a user (or yourself, on a fresh clone) through Hegemon setup without silently skipping optional components. The failure mode this skill prevents is: user runs `make setup && make node`, opens the Electron app, clicks "create wallet", and gets a confusing `walletd not found` error — because nothing in the default flow builds `walletd`.

# How to use this skill

You are the orchestrator. The user is in the repo root (`/Users/simon/dev/Hegemon` or wherever they cloned). Run the steps below in order. Narrate progress concisely. Verify each step before moving on.

# Step 1 — Detect current state

Before asking anything, run these checks in parallel and remember the results:

```bash
which cargo                                    # toolchain present?
which node && node --version                   # npm/node present?
which protoc                                   # substrate dep
test -x ./target/release/hegemon-node && echo NODE_BUILT
test -x ./target/release/walletd && echo WALLETD_BUILT
test -d ./hegemon-app/node_modules && echo NPM_INSTALLED
```

If `cargo` is missing, the user has not run `make setup` yet — set toolchains_needed=true.

# Step 2 — Ask the user one branching question

Use AskUserQuestion. Present three options:

- **(a) CLI node only** — *"Just run a Hegemon node from the terminal. Fastest, ~15 min cold build."*
- **(b) Desktop app** — *"Run the Electron wallet/node app. Adds walletd + npm install, ~25 min total."*
- **(c) Full contributor setup** — *"Everything in (b) plus `make check` to verify your environment passes fmt/lint/tests."*

Skip the question only if the user has already specified ("set up everything", "just the CLI", "I want to use the app"). When in doubt, ask.

# Step 3 — Execute, with verification

Run only the steps the user's branch requires. Skip any step whose output already exists per Step 1.

## 3a. Toolchains (all branches)

```bash
make setup
```

Verify: `which cargo` returns a path. If `make setup` fails, surface the error verbatim — do not retry blindly.

## 3b. Build the node (all branches)

```bash
make node
```

This is the long step (10–20 min cold). Tell the user before kicking it off so they don't think Claude has hung.

Verify: `./target/release/hegemon-node --version` runs without error.

## 3c. Build walletd (branches b, c)

```bash
make walletd
```

Verify: `test -x ./target/release/walletd && ./target/release/walletd --help` runs.

## 3d. Install JS deps (branches b, c)

```bash
cd hegemon-app && npm install
```

Verify: `test -d hegemon-app/node_modules`.

## 3e. Run checks (branch c only)

```bash
make check
```

This runs fmt + lint + the full test suite. Long. If it fails, do not block the user — surface the failure and let them decide.

# Step 4 — Print next-step commands

Once the build branch the user picked is complete, print exactly the commands they should run next. Do not run these yourself — they're long-running foreground processes the user controls.

**For all branches:**
```
HEGEMON_MINE=1 ./target/release/hegemon-node --dev --tmp
```

**For branches (b) and (c) — launching the desktop app:**
```
cd hegemon-app && npm run dev
```

# Important constraints

- **Do not silently skip walletd.** If you detect the user is heading toward the Electron app (asking about wallet creation, mentioning the GUI, etc.), confirm walletd is built. The whole point of this skill is to surface that fork, not bury it.
- **Ask before starting long builds** if the user hasn't already authorized them. `make node` on a cold cache pegs cores for 10+ minutes.
- **Do not destroy state.** If `target/release/hegemon-node` already exists, do not rebuild unless the user asks. Detect-then-skip.
- **macOS libclang quirk** — `make` targets call `./scripts/ensure-macos-libclang.sh` automatically; do not call cargo directly without setting `LIBCLANG_PATH` (see Makefile lines 8–19 for the macOS env handling).
- **Stash unrelated dirty state** before running setup if the user has uncommitted work — they may have left in-progress changes. Confirm with the user first.

# Reference: what each binary is for

| Binary | Built by | Used by |
|---|---|---|
| `hegemon-node` | `make node` | CLI node, Electron app's node manager |
| `walletd` | `make walletd` | Electron app's wallet daemon, `make wallet-demo`, testnet-join skill |

The Electron app's binary resolver (`hegemon-app/electron/binPaths.ts`) looks for both binaries in `target/release/` (and `target/debug/`), walking up from the app dir.
