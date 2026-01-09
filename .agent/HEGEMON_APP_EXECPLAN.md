# Hegemon Core Desktop App (Node + Wallet + Explorer)

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Maintained in accordance with `.agent/PLANS.md`.


## Purpose / Big Picture

After this work, users can run one desktop application that acts like "Bitcoin Core for Hegemon": it creates/unlocks a shielded wallet, starts/stops a local `hegemon-node`, and shows chain + wallet state (including mining) without needing the CLI.

Observable outcome: from a clean dev environment, running `npm run dev` in `hegemon-app/` opens an Electron window where a user can (1) create a wallet store and copy the primary `shca1...` address, (2) start a local dev node and enable mining to that address, (3) watch block height advance and see wallet balance rise after syncing, (4) send a shielded transfer, and (5) generate/verify a disclosure package for that payment.

This app is a GUI wrapper over existing Rust components (`hegemon-node` and the Rust `wallet` crate). It does not re-implement cryptography, proving, or key derivation in TypeScript.


## Progress

- [x] (2026-01-09) Rewrite ExecPlan to align with current `hegemon-node` + `wallet` code and runbooks.
- [ ] Milestone 0: Validate node + wallet CLI flows end-to-end.
- [x] Milestone 1: Scaffold `hegemon-app/` (Electron + Vite + React + Tailwind + BRAND.md tokens).
- [x] Milestone 2: Node manager (spawn/stop `hegemon-node`, RPC health, mining controls via RPC).
- [x] Milestone 3: Wallet integration v1 (use `wallet` CLI for init/status/sync/send; minimal parsing).
- [x] Milestone 4: Wallet integration v2 (replace parsing with `walletd` sidecar protocol).
- [x] Milestone 5: Wallet UX hardening (address book, consolidation UI, disclosure UI).
- [ ] Milestone 6: Explorer + mining dashboard tab (build views directly from RPC data).
- [ ] Milestone 7: Packaging and distribution (bundle binaries, signing, updates).


## Surprises & Discoveries

- Observation: Multi-machine dev networks require a shared raw chainspec; `--chain dev` produces incompatible genesis hashes across platforms.
  Evidence: `runbooks/two_person_testnet.md`.

- Observation: Chain properties advertise `tokenDecimals=12`, but the wallet and native-asset UX use 10^8 base units ("8 decimals") in practice.
  Evidence: `config/dev-chainspec.json` vs balance formatting in `wallet/src/bin/wallet.rs` and reward constants like `runtime/src/lib.rs` `MaxSubsidy`.

- Observation: The wallet binary's Substrate daemon HTTP API is currently a stub (`/health` only), so a GUI cannot use it for balances/txs yet.
  Evidence: `wallet/src/bin/wallet.rs` function `spawn_substrate_wallet_api`.


## Decision Log

- Decision: Keep all privileged operations (filesystem, spawning processes, RPC connections) in the Electron main process; the renderer is treated as untrusted UI.
  Rationale: This matches Electron security best practices (context isolation + least-privilege IPC) and reduces the blast radius of renderer bugs.
  Date/Author: 2026-01-09 / Agent

- Decision: Use Substrate JSON-RPC (WebSocket at `ws://127.0.0.1:9944` by default) plus Hegemon's custom RPC namespace (`hegemon_*`) for node status and mining control.
  Rationale: This matches how `wallet substrate-*` already interact with the node and avoids fragile log scraping.
  Date/Author: 2026-01-09 / Agent

- Decision: Display the native asset as "HGM" with 10^8 base units in the UI, even if chain properties claim 12 decimals.
  Rationale: This matches the wallet's current UX and avoids users seeing inconsistent balances between CLI and app.
  Date/Author: 2026-01-09 / Agent

- Decision: Use `HEGEMON_SEEDS` (IP:port, comma-separated) for PQ bootstrap peers rather than relying on Substrate `--bootnodes` multiaddrs.
  Rationale: The Substrate service reads `HEGEMON_SEEDS` for PQ-Noise bootstrapping (`node/src/substrate/service.rs`).
  Date/Author: 2026-01-09 / Agent

- Decision: Start with a "ship it" wallet integration that spawns the existing `wallet` binary, then replace parsing with a stable programmatic interface once UX is proven.
  Rationale: The Rust wallet already implements the hard parts (encrypted store, sync engine, proving, disclosure). Spawning it gets a working product quickly; `walletd` removes parsing brittleness without blocking the first usable app.
  Date/Author: 2026-01-09 / Agent

- Decision: Implement wallet integration v2 as a Rust sidecar process (`walletd`) that speaks newline-delimited JSON over stdio, owned by the Electron main process.
  Rationale: This avoids Node/Electron ABI coupling (native addons), is easy to bundle alongside `hegemon-node`, and lets us reuse the `wallet` crate directly with a testable protocol surface.
  Date/Author: 2026-01-09 / Agent


## Outcomes & Retrospective

- 2026-01-09: Landed `hegemon-app/` Electron scaffold with BRAND.md styling, node lifecycle controls, and wallet CLI integration (init/status/sync/send). Next step is to replace CLI parsing with `walletd`.
- 2026-01-09: Added `walletd` JSON sidecar plus disclosure/address book/consolidation UX wiring in the Electron app so wallet state no longer depends on parsing CLI output.


## Context and Orientation

Hegemon has three user-facing surfaces that this desktop app must integrate without re-implementing core cryptography:

1. The Substrate-based node binary `hegemon-node` (build via `make node`). It exposes JSON-RPC (HTTP + WebSocket) on port 9944 by default, and can mine PoW blocks when configured.
2. The Rust wallet (`wallet` crate and `wallet` binary). It stores shielded keys/notes in an encrypted local file and talks to a node over WebSocket RPC for sync and transaction submission (`wallet substrate-sync`, `wallet substrate-send`, disclosure tooling, etc).
3. The desktop UI surface (`hegemon-app/`), which will render chain state via JSON-RPC with optional `@polkadot/api` usage if needed.

Key files and directories for this plan:

    .agent/PLANS.md                    ExecPlan requirements
    DESIGN.md / METHODS.md             Protocol + operational intent
    BRAND.md                           Visual system for the desktop app
    node/                              `hegemon-node` crate + custom RPC endpoints
    wallet/                            Wallet store, sync engine, proving, disclosure
    hegemon-app/                       Electron desktop app (this plan)
    runbooks/two_person_testnet.md     Chainspec + bootstrapping constraints

Important Hegemon-specific behaviors the app must respect:

- Mining rewards are shielded notes. Mining requires a shielded recipient address (`HEGEMON_MINER_ADDRESS`) because there are no transparent balances.
- The wallet can only spend up to `MAX_INPUTS=2` notes per transaction today, so consolidation must be a first-class UX (not an edge case).
- Wallet stores are bound to a chain genesis hash. If the chain changes (different chainspec / wiped node), the wallet must force-rescan or create a new store.

Terms used in this plan:

- "Node": `hegemon-node` process, run locally by the app (child process) or externally by the user (remote node).
- "Wallet store": an encrypted file managed by the Rust `wallet` crate that contains derived keys, tracked notes, pending transactions, and sync cursors.
- "Shielded address": a bech32m string starting with `shca1...` produced by the wallet and used for receiving funds (including coinbase rewards).
- "RPC": JSON-RPC endpoints exposed by the node over HTTP/WebSocket; includes standard Substrate RPCs (`system_*`, `chain_*`) and Hegemon custom methods (`hegemon_*`).


## Plan of Work

Work in vertical slices so every milestone is a real, testable application rather than a UI mock.

Milestone 0 establishes ground truth by running existing CLI flows end-to-end: mine blocks, sync wallet, and submit a shielded transfer. The GUI must not be built on assumptions that contradict the actual node/wallet behavior.

Milestone 1 scaffolds an Electron app and applies BRAND.md tokens (colors, typography, spacing) so subsequent work is done in the real UI environment.

Milestone 2 implements node lifecycle management and RPC-driven status (height, peers, mining status). The app is already useful as a "node launcher + dashboard" even before wallet integration.

Milestone 3 implements a first wallet integration by calling the `wallet` binary as a subprocess. This is intentionally pragmatic: it gets wallet creation, syncing, and sending working quickly. Parsing must be minimal and defensive (only parse stable label lines like `Shielded Address:`).

Milestone 4 replaces parsing with `walletd`: a Rust binary that uses the `wallet` crate internally and exposes a strict JSON protocol over stdio. The Electron main process owns the `walletd` child process and treats it like an in-app daemon.

Milestone 5 hardens wallet UX around Hegemon realities: long addresses, anti-poisoning UX, `MAX_INPUTS=2` consolidation, and disclosure-on-demand.

Milestone 6 builds the explorer/mining views directly against node RPCs, preserving the same chain queries and 10^8 base-unit formatting used by the wallet.

Milestone 7 packages the desktop app for macOS/Windows/Linux and bundles the appropriate `hegemon-node` and `walletd` binaries (per-platform), including code signing and a coherent update strategy.


## Concrete Steps

All commands run from the repo root unless stated otherwise.

1. First-run toolchain setup (fresh clone):

    make setup

2. Build binaries used during desktop-app development:

    make node
    cargo build -p wallet --release

   Expected artifacts:

    target/release/hegemon-node
    target/release/wallet

   macOS note: if you see `Library not loaded: @rpath/libclang.dylib` while building, run build steps via `make` (so `LIBCLANG_PATH`/`DYLD_LIBRARY_PATH` are set) or export those variables yourself per `Makefile`.

3. Baseline end-to-end smoke test (this is the behavior the GUI will wrap):

    ./target/release/wallet init --store /tmp/hegemon-wallet --passphrase "test-pass"
    export HEGEMON_MINER_ADDRESS=$(
      ./target/release/wallet status --store /tmp/hegemon-wallet --passphrase "test-pass" --no-sync \
        | grep "Shielded Address:" \
        | awk '{print $3}'
    )
    HEGEMON_MINE=1 HEGEMON_MINER_ADDRESS="$HEGEMON_MINER_ADDRESS" \
      ./target/release/hegemon-node --dev --tmp

   In a second terminal, sync and verify the wallet observes mined rewards:

    ./target/release/wallet substrate-sync \
      --store /tmp/hegemon-wallet \
      --passphrase "test-pass" \
      --ws-url ws://127.0.0.1:9944

4. Scaffold the desktop app:

   Create `hegemon-app/` with Electron + Vite + React + TypeScript (template choice is not important as long as it supports context isolation and preload scripts):

    npm create electron-vite@latest hegemon-app -- --template react-ts
    cd hegemon-app
    npm install
    npm run dev

   Expected: an Electron window opens.

5. Apply BRAND.md tokens:

   Mirror the dashboard's token choices (Deep Midnight background `#0E1C36`, Ionosphere accent `#1BE7FF`, Space Grotesk + JetBrains Mono, 8px grid). Keep the renderer purely presentational; privileged work happens in the main process.

6. Implement node lifecycle in the Electron main process:

   Create `hegemon-app/electron/nodeManager.ts` that can spawn/stop `target/release/hegemon-node`, capture stdout/stderr, and provide status via JSON-RPC.

   At minimum, implement:

    - startNode({ chainSpecPath, dev, tmp, basePath, rpcPort, p2pPort, minerAddress, mineThreads, seeds })
    - stopNode()
    - rpcCall(method, params) (internal helper)
    - getNodeSummary() that calls `system_health`, `chain_getHeader`, `hegemon_consensusStatus`, and `hegemon_miningStatus`
    - setMiningEnabled(enabled, threads) using `hegemon_startMining` / `hegemon_stopMining`

   Chainspec handling requirements:

   - For single-machine dev, `--dev --tmp` is acceptable.
   - For multi-machine networks, the app must support selecting a raw chainspec file and passing it via `--chain <PATH>`. The UI should surface the warning from `runbooks/two_person_testnet.md` that chainspecs must be shared across machines.

   Example chainspec export command (boot node):

    ./target/release/hegemon-node build-spec --chain dev --raw > config/dev-chainspec.json

7. Implement wallet lifecycle v1 (CLI) in the Electron main process:

   Create `hegemon-app/electron/walletCli.ts` that shells out to `target/release/wallet` and returns structured results to the renderer.

   Required flows:

   - Create wallet store: `wallet init --store <PATH> [--passphrase <...>]`
   - Restore wallet store: `wallet restore --store <PATH> [--passphrase <...>]`
   - Read primary address + balances without syncing: `wallet status --store <PATH> --no-sync`
   - Sync: `wallet substrate-sync --store <PATH> --ws-url <WS> [--force-rescan]`
   - Send: `wallet substrate-send --store <PATH> --ws-url <WS> --recipients <FILE> --fee <N> [--auto-consolidate]`

   The recipients file is JSON: an array of objects matching `wallet::api::RecipientSpec`:

    [
      {"address":"shca1...","value":2500000000,"asset_id":0,"memo":"optional"},
      {"address":"shca1...","value":100000000,"asset_id":0,"memo":null}
    ]

   Values are base units. For the native asset, display `value / 100_000_000` as "HGM".

8. Implement wallet lifecycle v2 (`walletd`) and switch the app to it:

   Add a new workspace crate `walletd/` (binary) that:

   - links against the `wallet` crate and exposes operations over stdin/stdout
   - never prints secrets to stdout; logs go to stderr
   - accepts the store path and an unlock secret at startup (prefer reading the passphrase from stdin once, not as a CLI arg)
   - speaks newline-delimited JSON where each line is one request or response

   Minimum protocol surface (names are suggestions; keep it small and stable):

   - `status.get` -> returns primary address, balances, pending tx summaries, last synced height
   - `sync.once` with `{ ws_url, force_rescan }` -> runs one sync and returns counts + new height
   - `tx.send` with `{ ws_url, recipients: RecipientSpec[], fee, auto_consolidate }` -> builds + submits and returns tx hash
   - `disclosure.create` / `disclosure.verify` -> wraps the wallet's payment-proof tooling

   The Electron main process replaces `walletCli.ts` calls with a `walletdClient.ts` that manages the child process and maps requests/responses into typed results for the renderer.


## Validation and Acceptance

Milestone 2 is accepted when the app can start a local node and show:

- RPC reachable (clear green/red UX state)
- current block height advances in dev mode
- mining status is readable via `hegemon_miningStatus` (even if mining is disabled)
- if a miner address is configured, mining can be toggled via `hegemon_startMining` / `hegemon_stopMining` without restarting the node

Milestone 3 is accepted when the app can:

- create or restore a wallet store file and show the primary `shca1...` address
- start mining to that address (by setting `HEGEMON_MINER_ADDRESS` when spawning the node)
- sync the wallet and display a non-zero HGM balance after mining blocks
- send a shielded transfer to a second wallet address and observe it confirm after syncing

Milestone 4 is accepted when all Milestone 3 behaviors still work, but the app no longer parses human CLI output for wallet state. Wallet state must come from the `walletd` protocol.

Milestone 6 is accepted when the Explorer tab shows core data against a local node: recent blocks, shielded pool events, difficulty/hashrate, and shielded pool stats.


## Idempotence and Recovery

- Wallet stores are not interchangeable across chains. If the app detects a genesis mismatch, prompt the user to either force-rescan (equivalent to `wallet substrate-sync --force-rescan`) or pick the correct node/chainspec.

- Node state can always be reset by deleting the node base path. For development, prefer `--tmp` so state is automatically discarded on exit.

- Never expose RPC externally by default. If the user opts into remote RPC, present the hardening guidance from `runbooks/two_person_testnet.md` in-app and default to safe settings.


## Artifacts and Notes

Useful JSON-RPC probes (expected to return JSON without errors when a node is running):

    curl -s -H "Content-Type: application/json" \
      -d '{"id":1,"jsonrpc":"2.0","method":"system_health"}' \
      http://127.0.0.1:9944

    curl -s -H "Content-Type: application/json" \
      -d '{"id":1,"jsonrpc":"2.0","method":"hegemon_miningStatus"}' \
      http://127.0.0.1:9944


## Interfaces and Dependencies

The desktop app introduces a new Node project:

    hegemon-app/                       Electron + Vite project root
    hegemon-app/electron/main.ts        Main process entry
    hegemon-app/electron/preload.ts     Secure IPC bridge (renderer -> main)
    hegemon-app/electron/nodeManager.ts
    hegemon-app/electron/walletCli.ts   (wallet v1 integration)
    hegemon-app/electron/walletdClient.ts
    hegemon-app/src/                   Renderer React app

Wallet integration v2 introduces:

    walletd/                            New Rust binary crate (sidecar daemon)

Core JS dependencies belong in `hegemon-app/package.json` and should stay minimal: Electron, React, router, Tailwind, and a small JSON-RPC client. Only pull in `@polkadot/api` if the node RPCs are insufficient for required data; otherwise prefer raw JSON-RPC calls for the small set of methods we need.
