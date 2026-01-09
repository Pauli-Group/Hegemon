# Hegemon Desktop App - ExecPlan

> Single Electron app: node launcher + wallet + dashboard

## Vision

A unified desktop application that:
1. Manages wallet creation/import (required first—mining needs an address)
2. Launches and controls `hegemon-node` (mining or sync mode)
3. Displays chain/mining status beautifully (replaces terminal output)
4. Provides full wallet functionality with privacy-first UX

This is the "Bitcoin Core" of Hegemon—a full node wallet for power users and miners, with modern UX.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Electron Main Process                         │
├──────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────┐  │
│  │  Node Manager   │  │  Wallet Core    │  │  IPC Bridge         │  │
│  │  - spawn node   │  │  - WASM wallet  │  │  - renderer <-> main│  │
│  │  - log parsing  │  │  - key storage  │  │  - node <-> wallet  │  │
│  │  - health check │  │  - sync engine  │  │                     │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────────┘  │
│           │                    │                      │              │
│           ▼                    ▼                      ▼              │
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │                    hegemon-node (child process)                  ││
│  │                    ws://127.0.0.1:9944                          ││
│  └─────────────────────────────────────────────────────────────────┘│
└──────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌──────────────────────────────────────────────────────────────────────┐
│                       Electron Renderer Process                       │
├──────────────────────────────────────────────────────────────────────┤
│  React + Vite + Tailwind (reuse dashboard-ui components)             │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐│
│  │  Wallet    │ │  Node      │ │  Explorer  │ │  Settings          ││
│  │  - Balance │ │  - Status  │ │  - Blocks  │ │  - Network         ││
│  │  - Send    │ │  - Logs    │ │  - Events  │ │  - Storage         ││
│  │  - Receive │ │  - Mining  │ │  - Pool    │ │  - Display         ││
│  │  - History │ │  - Peers   │ │            │ │                    ││
│  │  - Contacts│ │            │ │            │ │                    ││
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘│
└──────────────────────────────────────────────────────────────────────┘
```

---

## Milestone 0: Project Scaffold

**Goal**: Electron + Vite + React project with brand styling

### Tasks
- [ ] Initialize Electron project with electron-vite or electron-forge
- [ ] Set up Vite + React + TypeScript for renderer
- [ ] Port Tailwind config and brand tokens from dashboard-ui
- [ ] Create main process structure (IPC handlers)
- [ ] Basic window with placeholder tabs

### Directory Structure
```
hegemon-app/
├── electron/
│   ├── main.ts              # Main process entry
│   ├── preload.ts           # Secure IPC bridge
│   ├── node-manager.ts      # Spawn/control hegemon-node
│   ├── wallet-manager.ts    # Wallet operations (wraps WASM)
│   └── ipc-handlers.ts      # IPC endpoint definitions
├── src/
│   ├── App.tsx              # Root component
│   ├── main.tsx             # Renderer entry
│   ├── pages/
│   │   ├── Wallet.tsx
│   │   ├── Node.tsx
│   │   ├── Explorer.tsx
│   │   └── Settings.tsx
│   ├── components/          # Reuse from dashboard-ui
│   └── lib/
│       ├── ipc.ts           # IPC client helpers
│       └── types.ts
├── package.json
├── electron.vite.config.ts
└── tailwind.config.js
```

### Acceptance Criteria
- `npm run dev` launches Electron window with branded UI
- Tab navigation between Wallet/Node/Explorer/Settings
- Build produces signed macOS .app (unsigned for dev)

---

## Milestone 1: Wallet First

**Goal**: Full wallet functionality before node launch

### 1.1 Wallet Creation/Import

**New wallet flow:**
1. Generate mnemonic (BIP-39 compatible or custom)
2. Display mnemonic with verification step
3. Set encryption passphrase
4. Create wallet file at `~/.hegemon/wallet.dat`

**Import wallet flow:**
1. Enter existing mnemonic OR
2. Select wallet file + enter passphrase
3. Decrypt and load

**Watch-only mode:**
1. Import incoming viewing key only
2. Can view balance but not spend

### 1.2 Wallet Dashboard

**Balance display:**
- Total HGM balance (8 decimal precision)
- Number of spendable notes
- Pending transactions
- Sync status indicator

**Address management:**
- Primary address (index 0) always shown
- "New address" button generates next diversifier
- Copy address with one click
- QR code display (large addresses need QR)

### 1.3 Contacts / Address Book

**Why this matters for shielded:**
- Addresses are 200+ characters (pk_recipient + diversifier + tag)
- Copy-paste errors are dangerous
- Address poisoning in shielded = sending to attacker's similar-looking address

**Implementation:**
```typescript
interface Contact {
  id: string;
  name: string;                    // User-chosen nickname
  address: string;                 // Full shielded address
  addressHash: string;             // First 8 chars for quick verify
  verifiedAt?: number;             // Timestamp of out-of-band verification
  notes?: string;                  // User notes
  transactionCount: number;        // Times sent to this address
  lastUsed?: number;
}
```

**Anti-poisoning measures:**
1. **Visual hash**: Show first 8 and last 8 chars prominently
2. **New address warning**: "First time sending to this address" 
3. **Verification badge**: User can mark address as verified (met in person, verified on call, etc.)
4. **Similar address detection**: Warn if address differs by <5% from existing contact
5. **Clipboard protection**: Clear clipboard after 60 seconds when address is copied

### 1.4 Transaction History

**Display columns:**
- Direction (sent/received/consolidation)
- Amount
- Counterparty (contact name or truncated address)
- Memo (decrypted if available)
- Status (pending/confirmed/failed)
- Confirmations
- Timestamp

**Details view:**
- Full transaction data
- Nullifiers spent (for sent)
- Commitments created
- Proof size
- Disclosure button (generate on-demand proof)

### 1.5 Send Flow

**Step 1: Recipient**
- Select from contacts OR
- Paste address (with validation)
- Show address verification prompt if new

**Step 2: Amount**
- Enter amount in HGM
- Show available balance
- Fee estimate (fixed or calculated)
- If insufficient single note → prompt consolidation

**Step 3: Memo (optional)**
- Free text memo (encrypted with note)
- Warn about memo privacy model

**Step 4: Confirm**
- Summary of all details
- "Send" button → proof generation
- Progress indicator during proving

**Step 5: Broadcast**
- Submit to node
- Return to history with pending status

### 1.6 Note Consolidation

**Problem:** Wallet has many small notes, can't spend in single tx (MAX_INPUTS = 2)

**Solution:** Consolidation wizard
1. Detect when notes need consolidation
2. Show plan: "X transactions needed to consolidate Y notes"
3. Execute sequentially with progress
4. Each consolidation tx sends to self

**Automatic vs Manual:**
- Manual: User triggers from wallet settings
- Automatic: Prompt when send requires it

### 1.7 Disclosure-on-Demand

**Use case:** User needs to prove a transaction happened to a third party (auditor, counterparty, etc.)

**UI flow:**
1. Select transaction from history
2. "Generate disclosure proof"
3. Choose what to disclose:
   - Recipient address: ☑
   - Amount: ☑
   - Memo: ☐
4. Generate DisclosurePackage
5. Export as JSON file or QR code
6. Record that disclosure was generated (audit trail)

**Verification UI:**
1. Import disclosure JSON
2. Verify proof cryptographically
3. Display verified claims

### Acceptance Criteria (Milestone 1)
- [ ] Create new wallet with passphrase encryption
- [ ] Import existing wallet file
- [ ] Display balance and addresses
- [ ] Address book with anti-poisoning UX
- [ ] Send transaction with proof generation
- [ ] Receive shows primary address + QR
- [ ] Transaction history with status updates
- [ ] Consolidation wizard works
- [ ] Disclosure proof generation and verification

---

## Milestone 2: Node Management

**Goal**: Launch and control hegemon-node from the app

### 2.1 Node Launcher

**First launch:**
1. Detect if hegemon-node binary exists
2. If not, prompt to download or specify path
3. Select mode: Mining or Sync-only
4. If mining: provide wallet address (from Milestone 1)
5. Configure data directory

**Mining mode:**
```bash
HEGEMON_MINE=1 ./hegemon-node \
  --chain config/dev-chainspec.json \
  --base-path ~/.hegemon/node \
  --miner-address <wallet_primary_address>
```

**Sync-only mode:**
```bash
./hegemon-node \
  --chain config/dev-chainspec.json \
  --base-path ~/.hegemon/node
```

### 2.2 Log Parsing & Display

**Parse node stdout for:**
- Block mined events → "🎉 Block mined!" notifications
- Sync progress → progress bar
- Peer connections → peer count
- Errors → error panel

**Log levels:**
- Info: Show in clean status area
- Debug: Hidden by default, toggle to show
- Error: Highlight in red, notify user

**Structured log display:**
```typescript
interface ParsedLogEntry {
  timestamp: Date;
  level: 'info' | 'debug' | 'warn' | 'error';
  category: 'mining' | 'sync' | 'network' | 'consensus' | 'other';
  message: string;
  metadata?: Record<string, unknown>;
}
```

### 2.3 Mining Dashboard

**Live stats:**
- Current difficulty (from pallet)
- Block time histogram (from node timing)
- Blocks mined this session
- Total rewards earned (sum of coinbase notes)

**Mining controls:**
- Pause/Resume (if supported)
- Hashrate display (if measurable)

### 2.4 Network Status

**Peer info:**
- Connected peer count
- Peer list with IDs (truncated)
- Connection quality indicators

**Sync status:**
- Current block height
- Best known block
- Sync percentage
- Estimated time to sync

### Acceptance Criteria (Milestone 2)
- [ ] Auto-detect or configure node binary path
- [ ] Launch node in mining or sync mode
- [ ] Parse logs into structured display
- [ ] Toggle debug log visibility
- [ ] Show mining stats when mining
- [ ] Display peer connections
- [ ] Clean shutdown on app quit

---

## Milestone 3: Explorer Integration

**Goal**: Reuse dashboard-ui explorer in Electron app

### 3.1 Port Dashboard Components

Migrate from dashboard-ui:
- StatCard
- BlockList
- EventFeed
- Mining page charts

Adapt for Electron:
- Remove Next.js dependencies
- Use IPC for API calls instead of direct WebSocket

### 3.2 Explorer Page

**Content:**
- Block height, shielded supply, commitments (from dashboard)
- Recent blocks list
- Shielded pool events feed

### 3.3 Shielded Pool Page

**Content:**
- Tree size, nullifiers, merkle root
- Pool balance

### Acceptance Criteria (Milestone 3)
- [ ] Explorer shows live chain data
- [ ] Shielded pool stats display
- [ ] Block list updates in real-time

---

## Milestone 4: Settings & Polish

### 4.1 Settings Page

**Network:**
- Node endpoint override
- Chain selection (mainnet/testnet/dev)

**Storage:**
- Wallet file location
- Node data directory
- Log retention

**Display:**
- Currency format (decimal places)
- Date/time format
- Theme (future: light/dark)

**Security:**
- Auto-lock timeout
- Change passphrase
- Export mnemonic (with confirmation)

### 4.2 Auto-Lock

- Lock wallet after N minutes of inactivity
- Require passphrase to unlock
- Clear sensitive data from memory on lock

### 4.3 Notifications

- Block mined → system notification
- Transaction received → system notification
- Sync complete → system notification

### 4.4 First-Run Experience

1. Welcome screen with branding
2. Choice: Create wallet / Import wallet
3. Wallet setup wizard
4. Choice: Mining / Sync-only
5. Node setup (data location)
6. Launch

### Acceptance Criteria (Milestone 4)
- [ ] Settings persist across restarts
- [ ] Auto-lock works correctly
- [ ] System notifications for key events
- [ ] First-run wizard guides new users

---

## Milestone 5: Packaging & Distribution

### 5.1 Build Configuration

**macOS:**
- Code signing with Apple Developer certificate
- Notarization for Gatekeeper
- Universal binary (x64 + arm64)
- .dmg installer with branding

**Windows:**
- Code signing with EV certificate
- NSIS or MSI installer
- Auto-updater integration

**Linux:**
- AppImage
- .deb for Debian/Ubuntu
- .rpm for Fedora/RHEL

### 5.2 Auto-Updater

- Check for updates on launch
- Download in background
- Prompt to restart to apply
- Verify update signatures

### 5.3 Bundled Node Binary

**Option A:** Bundle hegemon-node in app
- Larger download (~100MB)
- No external dependencies
- Version locked

**Option B:** Download on first run
- Smaller initial download
- Can update node independently
- Requires network

**Recommendation:** Option B for flexibility, with Option A as fallback

### Acceptance Criteria (Milestone 5)
- [ ] macOS: Signed .dmg that passes Gatekeeper
- [ ] Windows: Signed installer
- [ ] Linux: AppImage works on major distros
- [ ] Auto-updater downloads and applies updates

---

## Technical Decisions

### Framework: Electron + Vite

**Why Electron:**
- Proven for crypto wallets (Exodus, Wasabi, Ledger Live)
- Can spawn child processes (hegemon-node)
- Full filesystem access for wallet files
- Cross-platform with native look

**Why Vite (not Next.js):**
- No SSR needed in desktop app
- Faster dev builds
- Simpler Electron integration
- React components port directly

### Wallet Core: Native Node.js (not WASM initially)

**Reasoning:**
- Node.js can import native modules
- Direct FFI to wallet crate via napi-rs
- Better performance for proof generation
- WASM can be fallback for web extension later

**Alternative considered:** WASM
- Would need to compile entire wallet crate to WASM
- Plonky3 WASM compatibility uncertain
- Can revisit for browser extension

### IPC Security

**Context isolation:** Renderer cannot access Node.js APIs directly
**Preload scripts:** Expose only specific IPC channels
**Input validation:** Validate all IPC messages in main process

```typescript
// preload.ts
contextBridge.exposeInMainWorld('hegemon', {
  wallet: {
    getBalance: () => ipcRenderer.invoke('wallet:getBalance'),
    send: (params: SendParams) => ipcRenderer.invoke('wallet:send', params),
    // ...
  },
  node: {
    start: (mode: 'mining' | 'sync') => ipcRenderer.invoke('node:start', mode),
    stop: () => ipcRenderer.invoke('node:stop'),
    // ...
  }
});
```

---

## Dependencies

**Electron:**
- electron: ^28.0.0
- electron-vite: ^2.0.0 (or electron-forge)
- electron-builder: for packaging

**Renderer:**
- react: ^18.0.0
- react-router-dom: ^6.0.0
- @tanstack/react-query: for data fetching
- tailwindcss: ^3.0.0
- lucide-react: icons
- @polkadot/api: ^16.0.0 (for RPC)

**Main process:**
- @aspect-dev/napi-rs: for native Rust bindings (optional)
- electron-store: for settings persistence
- node-pty: for terminal emulation (if showing raw logs)

---

## Timeline Estimate

| Milestone | Duration | Dependencies |
|-----------|----------|--------------|
| M0: Scaffold | 1 week | None |
| M1: Wallet | 3 weeks | M0 |
| M2: Node Manager | 2 weeks | M0, M1 (for mining address) |
| M3: Explorer | 1 week | M0, M2 (for node connection) |
| M4: Settings | 1 week | M0-M3 |
| M5: Packaging | 1 week | M0-M4 |

**Total:** ~9 weeks to production-ready

---

## Open Questions

1. **Mnemonic format:** Use BIP-39 or custom? (BIP-39 for familiarity, but our key derivation differs)
2. **Multi-wallet:** Support multiple wallet files? (Start with single, add later)
3. **Hardware wallet:** Ledger/Trezor integration? (Future milestone)
4. **Mobile:** React Native port? (Separate project, share wallet core)
5. **Node binary bundling:** Include in app or download? (Download for flexibility)

---

## Success Metrics

**Demo quality:**
- Launches in <3 seconds
- Wallet creation flow <2 minutes
- Transaction sending <30 seconds (including proof)
- Mining status visible within 1 block of starting

**Production quality:**
- No data loss on crash
- Secure key storage
- Passes code signing on all platforms
- Auto-updater works reliably
