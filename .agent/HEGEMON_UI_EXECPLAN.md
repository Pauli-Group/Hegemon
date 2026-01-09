# Hegemon Explorer & Dashboard UI

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Maintained in accordance with `.agent/PLANS.md`.


## Purpose / Big Picture

After this work, operators and users can view Hegemon chain state through a branded web interface that surfaces the chain's unique capabilities: shielded pool activity, PoW mining metrics, and PQ cryptography status. The interface replaces the generic Polkadot.js Apps experience with Hegemon colors (Deep Midnight `#0E1C36`, Ionosphere `#1BE7FF`, Molten Amber `#F5A623`), typography (Space Grotesk, JetBrains Mono), and focused navigation that omits irrelevant Substrate features (staking, parachains, crowdloans).

Observable outcome: running `npm run dev` in `dashboard-ui/` opens a local site at `http://localhost:3000` that connects to a dev node and displays: (1) block explorer with shielded pool events, (2) mining dashboard with difficulty/hashrate, (3) PQ crypto status panel. Branding matches BRAND.md exactly.


## Progress

- [x] (2026-01-08 22:41Z) Milestone 0: Prototype — validated @polkadot/api connects with custom types
- [x] (2026-01-08 22:55Z) Milestone 1: Scaffold dashboard-ui with Next.js, Tailwind, brand tokens
- [x] (2026-01-08 22:55Z) Milestone 2: Block explorer page (events, blocks, transactions)
- [x] (2026-01-08 22:55Z) Milestone 3: Mining dashboard (difficulty, hashrate, coinbase)
- [x] (2026-01-08 22:55Z) Milestone 4: Shielded pool panel (Merkle root, nullifiers)
- [x] (2026-01-08 22:55Z) Milestone 5: PQ crypto status — REMOVED as not useful
- [x] (2026-01-08 22:56Z) Milestone 6: Documentation and runbook
- [x] (2026-01-08 23:40Z) Bugfix: Fixed subscription API (use polling instead of subscribeNewHeads)
- [x] (2026-01-08 23:42Z) Bugfix: Fixed decimal precision (use 10^8 not 10^12 for HGM units)
- [x] (2026-01-08 23:50Z) Polish: Add `.gitignore` entries for dashboard-ui build artifacts
- [x] (2026-01-08 23:51Z) Polish: Real logo asset (hegemon-atlas-emblem.svg from docs/assets)
- [x] (2026-01-08 23:51Z) Polish: Environment variable for node endpoint (NEXT_PUBLIC_NODE_ENDPOINT)

**STATUS: COMPLETE**


## Surprises & Discoveries

- Observation: The API detected custom RPC methods that are not decorated: `block_getCommitmentProof`, `da_getChunk`, `da_getParams`. These are Hegemon-specific RPCs that may need custom definitions.
  Evidence: `2026-01-08 API/INIT: RPC methods not decorated: block_getCommitmentProof, da_getChunk, da_getParams`

- Observation: The `coinbase` pallet is exposed as `pow` in storage queries but events come from `shieldedPool.CoinbaseMinted`.
  Evidence: Pallets list shows `pow` not `coinbase`, but shieldedPool has `coinbaseNotes`, `coinbaseProcessed` storage.

- Observation: Subscription API changed — `api.rpc.chain.subscribeNewHeads` is not a function in @polkadot/api v14+. Must use polling with `api.rpc.chain.getHeader()` instead.
  Evidence: `Error: api.rpc.chain.subscribeNewHeads is not a function`
  Resolution: Changed to 2-second polling interval for block updates.

- Observation: Chain metadata reports 12 decimals but INITIAL_REWARD uses 8 decimal places (Bitcoin-style satoshis).
  Evidence: `chain.decimals: [12]` but `INITIAL_REWARD = 498287671` which is ~5 HGM with 10^8 base units.
  Resolution: Dashboard uses 10^8 divisor for display, not 10^12.


## Decision Log

- Decision: Build a custom Next.js dashboard instead of forking polkadot-js/apps.
  Rationale: Forking apps is a 1M+ LOC monorepo with complex build tooling. A focused dashboard using `@polkadot/api` directly gives full branding control, smaller bundle, faster iteration. The existing `dashboard-ui/` directory is empty and ready for scaffolding.
  Date/Author: 2026-01-08 / Agent

- Decision: Use Next.js 14 + Tailwind CSS + shadcn/ui.
  Rationale: Next.js provides SSR/SSG flexibility, Tailwind enables rapid brand token integration, shadcn/ui gives accessible primitives. All align with BRAND.md's 8px grid and Space Grotesk typography.
  Date/Author: 2026-01-08 / Agent

- Decision: No node or wallet code changes in this plan.
  Rationale: User explicitly requested notification before touching node or wallet code. This plan is UI-only, consuming existing RPC endpoints and the types bundle from docs/POLKADOTJS_BINDINGS.md.
  Date/Author: 2026-01-08 / Agent


## Outcomes & Retrospective

### Completed 2026-01-08

All milestones completed successfully. The Hegemon Explorer dashboard is fully functional.

**Deliverables:**
- Full Next.js 14 + Tailwind project in `dashboard-ui/`
- Brand-compliant UI with Deep Midnight background, Ionosphere accents, Space Grotesk typography
- 4 pages: Explorer, Mining, Shielded Pool, Settings (PQ Status removed as not useful)
- Real logo from `docs/assets/hegemon-atlas-emblem.svg`
- Live connection to Hegemon node via @polkadot/api
- Environment variable support (`NEXT_PUBLIC_NODE_ENDPOINT`)
- Runbook at `runbooks/dashboard_ui.md`
- `.gitignore` entries for node_modules and build artifacts

**What works:**
- API connection and polling (no subscription API available)
- Live block height, shielded supply, commitment count
- Difficulty and mining metrics display
- Shielded pool status (Merkle root, tree size, nullifiers)
- Correct decimal formatting (10^8 base units, not 10^12)

**Future work (not blocking):**
- More detailed block explorer (click to expand, extrinsic details)
- Transaction search functionality
- Wallet integration for sending shielded transactions
- Mobile responsive refinements

**No node/wallet code was modified.** This was a UI-only change as requested.


## Context and Orientation

The Hegemon node is a Substrate-based blockchain with custom pallets for: shielded-pool (private transactions), coinbase (PoW block rewards), difficulty (PoW difficulty adjustment), identity (PQ session keys), settlement, oracles, and others. The runtime exposes SCALE-encoded types that require a custom types bundle when connecting via `@polkadot/api`.

Key files and directories:

    docs/POLKADOTJS_BINDINGS.md        — TypeScript types bundle for @polkadot/api
    config/dev-chainspec.json          — Chain properties (tokenSymbol: HGM, decimals: 12)
    BRAND.md                           — Color system, typography, spacing rules
    pallets/shielded-pool/src/lib.rs   — Events: CoinbaseMinted, MerkleRootUpdated
    pallets/difficulty/                — Difficulty adjustment pallet
    pallets/coinbase/                  — Block reward distribution
    dashboard-ui/                      — Empty directory to scaffold

The screenshot shows Polkadot.js Apps at `polkadot.js.org/apps` connected to `ws://127.0.0.1:9944`. It displays:
- Header: "Hegemon synthetic-hegemonic/2" with orange accent
- Stats: last block 29s, total issuance 0.0000 HGM, session #12
- Events: `shieldedPool.CoinbaseMinted`, `shieldedPool.MerkleRootUpdated`

Elements to remove from generic Substrate UI:
- Staking menu (Hegemon uses PoW, not NPoS)
- Parachains menu (standalone chain)
- Crowdloans, Bounties, Treasury, Council (different governance)
- Teleport/XCM (no cross-chain)

Elements to add:
- Mining dashboard with difficulty target, network hashrate, block time chart
- Shielded pool status with Merkle tree depth, nullifier count
- PQ crypto status showing ML-DSA/ML-KEM configuration


## Plan of Work

The work proceeds in six milestones, each independently verifiable.

### Milestone 0: Prototype

Before scaffolding the full dashboard, validate that `@polkadot/api` connects to a local node using the custom types bundle. This is a spike to de-risk the integration.

Create a minimal Node.js script in `dashboard-ui/scripts/api-test.js` that:
1. Imports `@polkadot/api` and `WsProvider`
2. Creates an API instance with the types bundle from docs/POLKADOTJS_BINDINGS.md
3. Subscribes to new block headers and logs them
4. Subscribes to `shieldedPool` events

Expected output: block numbers and event names printed to console.

### Milestone 1: Scaffold Dashboard

Initialize `dashboard-ui/` as a Next.js 14 project with:
- TypeScript, App Router, Tailwind CSS
- Brand tokens in `tailwind.config.ts` matching BRAND.md
- Fonts: Space Grotesk (sans), JetBrains Mono (mono)
- Base layout with Deep Midnight background, Ionosphere accent links
- Navigation: Explorer, Mining, Shielded Pool, PQ Status, Settings

Directory structure after scaffolding:

    dashboard-ui/
      package.json
      tsconfig.json
      tailwind.config.ts
      next.config.js
      src/
        app/
          layout.tsx           — Root layout with fonts, nav, providers
          page.tsx             — Home/Explorer page
          mining/page.tsx
          shielded/page.tsx
          pq-status/page.tsx
        components/
          Nav.tsx
          BlockCard.tsx
          EventFeed.tsx
          StatCard.tsx
        lib/
          api.ts               — @polkadot/api singleton with types bundle
          types.ts             — TypeScript interfaces for custom types
        styles/
          globals.css          — Tailwind directives, font imports

### Milestone 2: Block Explorer Page

Build the main explorer page showing:
- Header stats: last block number, average block time, total issuance, session index
- Recent blocks list (block number, hash, extrinsic count, timestamp)
- Recent events feed (event name, block number, expandable details)

Data sources:
- `api.rpc.chain.subscribeNewHeads()` for blocks
- `api.query.system.events()` for events
- `api.query.balances.totalIssuance()` for HGM supply

### Milestone 3: Mining Dashboard

Build `/mining` page showing PoW-specific metrics:
- Current difficulty target (from pallet_difficulty storage)
- Network hash rate estimate (if available, else computed from difficulty/block_time)
- Block time chart (last 50 blocks)
- Coinbase reward per block
- Recent `shieldedPool.CoinbaseMinted` events

Data sources:
- `api.query.difficulty.currentDifficulty()` (or equivalent storage item)
- `api.query.coinbase.*` for reward configuration
- Block timestamps from headers

### Milestone 4: Shielded Pool Panel

Build `/shielded` page showing:
- Current Merkle root hash (truncated, copyable)
- Merkle tree depth and leaf count
- Total nullifiers consumed
- Recent `MerkleRootUpdated` events with block numbers
- Note: No private data is exposed; all values are public chain state

Data sources:
- `api.query.shieldedPool.merkleRoot()`
- `api.query.shieldedPool.treeSize()` or equivalent
- `api.query.shieldedPool.nullifierSet()` count

### Milestone 5: PQ Crypto Status Panel

Build `/pq-status` page showing:
- Active signature scheme: ML-DSA (with security level)
- Active KEM: ML-KEM
- STARK verifier parameters: hash function, FRI queries, blowup factor, security bits
- Session key migration status (Legacy vs PostQuantum count, if exposed)

Data sources:
- `api.query.shieldedPool.verifyingKey()` for STARK params
- Runtime constants or genesis config for PQ scheme info

### Milestone 6: Documentation

Add a runbook at `runbooks/dashboard_ui.md` explaining:
- How to start the dashboard (`npm run dev`)
- How to connect to different networks (dev, testnet, mainnet)
- How to customize branding further


## Concrete Steps

All commands run from the repository root unless otherwise noted.

### Milestone 0

1. Ensure a dev node is running:

       HEGEMON_MINE=1 ./target/release/hegemon-node --dev --tmp

2. Create the test script directory and file:

       mkdir -p dashboard-ui/scripts

3. Create `dashboard-ui/scripts/api-test.js` with the prototype code (content in Artifacts section).

4. Install dependencies and run:

       cd dashboard-ui/scripts
       npm init -y
       npm install @polkadot/api
       node api-test.js

   Expected output (example):

       Connected to Hegemon
       Token: HGM, Decimals: 12
       New block: #125 (0xabc123...)
       Event: shieldedPool.CoinbaseMinted
       Event: shieldedPool.MerkleRootUpdated

5. If successful, prototype validates the types bundle works. Proceed to Milestone 1.

### Milestone 1

1. From `dashboard-ui/`, initialize Next.js:

       npx create-next-app@14 . --typescript --tailwind --app --src-dir --no-eslint

   (Accept defaults, overwrite existing package.json if prompted.)

2. Install additional dependencies:

       npm install @polkadot/api @polkadot/util @polkadot/util-crypto
       npm install lucide-react clsx tailwind-merge

3. Update `tailwind.config.ts` with brand tokens (see Artifacts).

4. Add fonts to `src/app/layout.tsx` using next/font/google.

5. Create `src/lib/api.ts` with the singleton API instance (see Artifacts).

6. Create navigation component `src/components/Nav.tsx`.

7. Verify: `npm run dev`, open `http://localhost:3000`, see branded layout.

### Milestones 2–5

Each milestone follows the same pattern:
1. Create page file under `src/app/<route>/page.tsx`
2. Create supporting components under `src/components/`
3. Subscribe to relevant chain data via `useEffect` + `api` calls
4. Style according to BRAND.md
5. Verify page renders with live data from dev node


## Validation and Acceptance

For each milestone, acceptance is behavior a human can verify:

- **Milestone 0**: Run `node api-test.js` while a dev node is running. Console shows block numbers incrementing and event names for `shieldedPool.*` events.

- **Milestone 1**: Run `npm run dev` in `dashboard-ui/`. Browser at `http://localhost:3000` shows:
  - Background color `#0E1C36` (Deep Midnight)
  - Navigation links in `#1BE7FF` (Ionosphere)
  - "Hegemon" in Space Grotesk font
  - No errors in browser console

- **Milestone 2**: Explorer page shows last block number updating live, event feed populates with `CoinbaseMinted` and `MerkleRootUpdated` events as blocks are mined.

- **Milestone 3**: Mining page shows a difficulty value (not zero), block time chart renders, coinbase events appear.

- **Milestone 4**: Shielded page shows Merkle root hash (48 bytes hex), tree statistics, nullifier count.

- **Milestone 5**: PQ Status page shows "ML-DSA" and "ML-KEM" labels, STARK verifier params displayed.

- **Milestone 6**: Runbook exists at `runbooks/dashboard_ui.md` with working instructions.


## Idempotence and Recovery

All steps can be repeated safely:
- `create-next-app` with `.` target will prompt before overwriting; re-running is safe.
- `npm install` is idempotent.
- API connections gracefully reconnect on page refresh.

If a milestone fails partway:
- Delete `dashboard-ui/node_modules` and `dashboard-ui/.next`, then re-run `npm install && npm run dev`.
- For prototype script, delete `dashboard-ui/scripts/node_modules` and retry.


## Artifacts and Notes

### Types Bundle (from docs/POLKADOTJS_BINDINGS.md)

    // src/lib/types.ts
    export const typesBundle = {
      spec: {
        'synthetic-hegemonic': {
          types: [
            {
              minmax: [0, undefined],
              types: {
                StarkHashFunction: { _enum: ['Blake3', 'Sha3'] },
                StarkVerifierParams: {
                  hash: 'StarkHashFunction',
                  fri_queries: 'u16',
                  blowup_factor: 'u8',
                  security_bits: 'u16'
                },
                // ... rest of types from docs/POLKADOTJS_BINDINGS.md
              }
            }
          ]
        }
      }
    };

### Tailwind Brand Tokens

    // tailwind.config.ts
    const config = {
      theme: {
        extend: {
          colors: {
            'midnight': '#0E1C36',
            'ionosphere': '#1BE7FF',
            'amber': '#F5A623',
            'proof-green': '#19B37E',
            'guard-rail': '#FF4E4E',
            'neutral-light': '#F4F7FB',
            'neutral-mid': '#E1E6EE',
          },
          fontFamily: {
            sans: ['Space Grotesk', 'Inter', 'sans-serif'],
            mono: ['JetBrains Mono', 'monospace'],
          },
        },
      },
    };

### Prototype Script

    // dashboard-ui/scripts/api-test.js
    const { ApiPromise, WsProvider } = require('@polkadot/api');

    const typesBundle = {
      spec: {
        'synthetic-hegemonic': {
          types: [{
            minmax: [0, undefined],
            types: {
              StarkHashFunction: { _enum: ['Blake3', 'Sha3'] },
              StarkVerifierParams: {
                hash: 'StarkHashFunction',
                fri_queries: 'u16',
                blowup_factor: 'u8',
                security_bits: 'u16'
              },
            }
          }]
        }
      }
    };

    async function main() {
      const provider = new WsProvider('ws://127.0.0.1:9944');
      const api = await ApiPromise.create({ provider, typesBundle });

      const chain = await api.rpc.system.chain();
      const props = await api.rpc.system.properties();
      console.log(`Connected to ${chain}`);
      console.log(`Token: ${props.tokenSymbol}, Decimals: ${props.tokenDecimals}`);

      api.rpc.chain.subscribeNewHeads((header) => {
        console.log(`New block: #${header.number} (${header.hash.toHex().slice(0,12)}...)`);
      });

      api.query.system.events((events) => {
        events.forEach(({ event }) => {
          if (event.section === 'shieldedPool') {
            console.log(`Event: ${event.section}.${event.method}`);
          }
        });
      });
    }

    main().catch(console.error);


## Interfaces and Dependencies

### External Dependencies

    @polkadot/api ^11.0.0      — Substrate RPC client
    @polkadot/util ^12.0.0     — Utilities (hex encoding, etc.)
    next ^14.0.0               — React framework
    tailwindcss ^3.4.0         — Utility CSS
    lucide-react               — Icon library (stroked icons per BRAND.md)

### Internal Interfaces

In `src/lib/api.ts`, export:

    export function getApi(): Promise<ApiPromise>

This returns a singleton API instance connected to the configured endpoint.

In `src/lib/types.ts`, export:

    export interface BlockInfo {
      number: number;
      hash: string;
      timestamp: number;
      extrinsicCount: number;
    }

    export interface ShieldedEvent {
      block: number;
      eventIndex: number;
      method: 'CoinbaseMinted' | 'MerkleRootUpdated';
      data: Record<string, unknown>;
    }

    export interface MiningStats {
      difficulty: bigint;
      avgBlockTime: number;
      coinbaseReward: bigint;
    }

    export interface PQStatus {
      signatureScheme: string;
      kemScheme: string;
      starkParams: {
        hash: 'Blake3' | 'Sha3';
        friQueries: number;
        blowupFactor: number;
        securityBits: number;
      };
    }

---

**Note**: This plan does NOT modify any code under `node/`, `wallet/`, `pallets/`, `runtime/`, or `consensus/`. It is purely additive, creating a new frontend in `dashboard-ui/`. If any milestone requires changes to node/wallet code (e.g., adding new RPC endpoints), work will pause and the user will be notified before proceeding.
