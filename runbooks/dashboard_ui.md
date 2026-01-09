# Hegemon Dashboard UI

This runbook describes how to run and develop the Hegemon Explorer dashboard.

## Prerequisites

- Node.js 18+ and npm
- A running Hegemon node (local or remote)

## Quick Start

1. **Start a local dev node** (if not already running):

   ```bash
   HEGEMON_MINE=1 ./target/release/hegemon-node --dev --tmp
   ```

2. **Start the dashboard**:

   ```bash
   cd dashboard-ui
   npm install
   npm run dev
   ```

3. **Open in browser**: Navigate to http://localhost:3000

## Pages

| Route | Description |
|-------|-------------|
| `/` | Block explorer with recent blocks and shielded pool events |
| `/mining` | PoW mining metrics: difficulty, block time chart, coinbase info |
| `/shielded` | Shielded pool status: Merkle root, tree size, nullifier count |
| `/pq-status` | Post-quantum cryptography status: ML-DSA, ML-KEM, STARK params |
| `/settings` | Connection settings and endpoint configuration |

## Connecting to Different Networks

### Local Development Node
```
ws://127.0.0.1:9944
```

### Testnet
```
wss://testnet.hegemon.network
```

### Mainnet
```
wss://rpc.hegemon.network
```

To change the endpoint, visit the Settings page or modify the `endpoint` prop passed to `<ApiProvider>` in `src/app/layout.tsx`.

## Development

### Project Structure

```
dashboard-ui/
├── src/
│   ├── app/                    # Next.js App Router pages
│   │   ├── layout.tsx          # Root layout with fonts and nav
│   │   ├── page.tsx            # Explorer home page
│   │   ├── mining/page.tsx     # Mining dashboard
│   │   ├── shielded/page.tsx   # Shielded pool status
│   │   ├── pq-status/page.tsx  # PQ crypto status
│   │   └── settings/page.tsx   # Connection settings
│   ├── components/             # Reusable UI components
│   │   ├── Nav.tsx             # Navigation bar
│   │   ├── StatCard.tsx        # Stat display card
│   │   ├── BlockList.tsx       # Recent blocks list
│   │   └── EventFeed.tsx       # Event feed display
│   ├── lib/
│   │   └── types.ts            # Custom types bundle for @polkadot/api
│   └── providers/
│       └── ApiProvider.tsx     # React context for API connection
├── tailwind.config.ts          # Tailwind with Hegemon brand tokens
├── package.json
└── scripts/
    └── api-test.js             # Standalone API connection test
```

### Brand Colors (from BRAND.md)

| Token | Hex | Usage |
|-------|-----|-------|
| `midnight` | `#0E1C36` | Primary background |
| `ionosphere` | `#1BE7FF` | Links, accent, focus states |
| `amber` | `#F5A623` | Alerts, warnings |
| `proof-green` | `#19B37E` | Success states |
| `guard-rail` | `#FF4E4E` | Error states |
| `neutral-light` | `#F4F7FB` | Text on dark |
| `neutral-mid` | `#E1E6EE` | Secondary text |

### Fonts

- **Sans**: Space Grotesk (primary UI)
- **Mono**: JetBrains Mono (hashes, code, numbers)

### Building for Production

```bash
cd dashboard-ui
npm run build
npm start
```

The production build outputs static pages that can be deployed to any static hosting.

## Troubleshooting

### Connection refused

Ensure the Hegemon node is running and accepting WebSocket connections on the configured port (default: 9944).

### Events not appearing

The event feed only shows `shieldedPool.*` events. If mining is disabled (`HEGEMON_MINE=0`), no coinbase events will appear.

### Type errors

If the node's runtime has been upgraded with new types, update `src/lib/types.ts` to match `docs/POLKADOTJS_BINDINGS.md`.
