# zkSync Bounty Platform Prototype

This document describes a shippable prototype for a bounty platform that settles escrow, review, and payout logic on zkSync. It focuses on deliverable contract APIs, sequencing for off-chain services, and UX hooks that fit the monorepo's wallet and dashboard expectations.

## Goals and guardrails
- **Fast, cheap settlement:** All core interactions (create bounty, fund escrow, submit work, accept/reject, dispute) are single-transaction flows on zkSync Era with multisig-capable account abstraction (AA) wallets.
- **Deterministic payouts:** Funds are locked in per-bounty escrows, released only through explicit state transitions with audited invariants.
- **Multi-asset support:** Stablecoin-first (USDC/DAI) with optional native ETH; ERC-20 list is gated by an allowlist to avoid illiquid tokens.
- **Censorship resistance:** Dispute and timeout logic prevent stuck funds even if a sponsor becomes unresponsive.
- **Auditable trail:** Every transition emits typed events that indexers mirror into the dashboard, keeping the chain canonical.

## Contract architecture
All contracts are written for zkSync Era and compiled with the official zkSync Solidity toolchain (solc 0.8.20 with zkSync extensions). Upgradeability uses transparent proxies guarded by a 2-of-3 SLH-DSA governance multisig to keep parity with the repo's PQ governance posture.

### Registry + factory
- `BountyRegistry` tracks the latest `BountyEscrow` implementation and deploys minimal proxies per bounty via `create2`.
- `createBounty(CreateParams)` arguments:
  - `sponsor` AA address; `paymaster` address if gas sponsoring is requested.
  - `asset` ERC-20 token (allowlisted) and `fundingAmount`.
  - `deadline` (unix seconds), `reviewWindow` (seconds), `disputeWindow` (seconds).
  - `arbiter` optional address; if zero, platform arbitration module handles disputes.
  - `metadataURI` (ipfs / https) with task details and acceptance criteria hash.
- Emits `BountyCreated(id, sponsor, asset, fundingAmount, deadline, arbiter, metadataURI, implementation)`.

### Escrow lifecycle
Each `BountyEscrow` proxy holds a single bounty with the following states: `Open → Submitted → Accepted/Rejected → Disputed → Resolved → Paid/Refunded/Slashed`.

Key functions (state-gated):
- `fund()` – transfers `fundingAmount` from sponsor; reverts unless token is allowlisted and escrow is `Open`.
- `submitWork(bytes32 deliverableHash, string evidenceURI)` – callable by hunter while `Open` and before `deadline`; captures immutable commitment to the deliverable.
- `acceptWork()` – sponsor or designated reviewer marks bounty `Accepted` within `reviewWindow` after submission; triggers payout to hunter.
- `rejectWork(string reasonURI)` – sponsor rejects; bounty stays `Open` and can accept new submissions until `deadline`.
- `escalateDispute(string reasonURI)` – hunter can escalate after rejection or timeout; moves to `Disputed` and assigns arbiter.
- `resolveDispute(bool hunterWins, uint256 hunterPayout, string verdictURI)` – arbiter or platform module resolves; enforces `hunterPayout <= fundingAmount` and `hunterPayout >= minimumGuarantee` (if configured).
- `timeoutPayout()` – if `reviewWindow` + `gracePeriod` passes without sponsor action, hunter can trigger auto-accept to prevent griefing.
- `refund()` – sponsor withdraws funds if no valid submission arrived by `deadline`.

Events surface every transition (`SubmissionReceived`, `WorkAccepted`, `WorkRejected`, `DisputeOpened`, `DisputeResolved`, `PayoutReleased`, `Refunded`).

### zkSync-specific features
- **AA-native flows:** All functions assume account abstraction; signatures use EIP-712 domain binding to each proxy. Sponsors can require ML-DSA-derived session keys via the AA hook for continuity with the repo's PQ signing goals, even though zkSync enforces ECDSA on L1 bridges.
- **Paymasters:** Sponsors can register a paymaster to cover gas for hunters; the registry enforces per-bounty gas budgets and recovers unused ETH to the sponsor on payout.
- **Native bridges:** Stablecoins enter via zkSync native bridges; the registry exposes `bridgeAndCreate` helper that waits for finality, funds escrow, then atomically deploys the bounty.
- **Commit-reveal optionality:** For public contests, `submitWork` can accept a `blindedHash` with later `reveal(blinding, deliverableURI)` to prevent solution sniping before the deadline.

## Off-chain services
- **Indexer:** Listens to registry + escrow events, normalizes state, and hydrates the dashboard UI. Critical mappings: bounty metadata, current state, deadlines, arbiter identity, paymaster budgets, and dispute outcomes.
- **Arbitration module:** If `arbiter == address(0)`, the platform provides an AA account with policy scripts (triage by category, SLA timers, optional staking) to resolve disputes. Decisions are signed and submitted on-chain.
- **Deliverable storage:** Deliverables live off-chain (IPFS/S3) with `deliverableHash` anchoring integrity. Evidence URIs include structured JSON with timestamps and proof-of-work artifacts.
- **Notification + reminders:** Cron-backed service triggers reminders for impending deadlines and auto-timeout windows; integrates with wallet push and email.

## User journey
1. **Sponsor drafts bounty:** Uses dashboard to craft requirements, selects token and funding, picks arbitration mode, and posts metadata to IPFS.
2. **Funding + deployment:** Dashboard calls `createBounty`, optionally `bridgeAndCreate` if funds sit on L1. Sponsor signs with AA wallet; paymaster configuration is stored.
3. **Hunter submits work:** After completing the task, hunter submits `deliverableHash` + `evidenceURI`. Gas may be covered by sponsor’s paymaster.
4. **Review:** Sponsor accepts (payout) or rejects (loop). If no response by `reviewWindow`, hunter calls `timeoutPayout`.
5. **Dispute:** If escalated, arbiter resolves and finalizes payout split.
6. **Payout + cleanup:** Tokens transfer to hunter (and arbiter fee if configured); leftover paymaster ETH is reclaimed; indexer updates status to `Paid` or `Refunded`.

## Security and compliance considerations
- **Invariant checks:** Escrow forbids reentrancy on payout/refund, enforces single-active-submission semantics unless explicitly configured otherwise, and gates token list via registry-controlled allowlist updates.
- **PQ posture:** Even though zkSync L2 inherits ECDSA from L1, session keys and off-chain signing flows for dashboard actions use the repo’s ML-DSA helpers. Governance for upgrades uses SLH-DSA multisig to match `DESIGN.md` guidance.
- **Auditability:** All contract code includes exhaustive event logs; off-chain indexer mirrors them into reproducible JSON for auditors. Proxies are upgradable only through time-locked governance transactions.
- **Abuse mitigation:** Rate limits for paymaster sponsorship per hunter address, optional KYC gating for high-value bounties, and per-category dispute SLAs to prevent backlog abuse.

## Prototype delivery milestones
1. **Week 1:** Draft Solidity interfaces, event schemas, and Foundry/zkSync tests that assert lifecycle transitions and invariant checks. Deploy registry + first escrow via local zkSync devnet.
2. **Week 2:** Wire dashboard form → `createBounty` call with paymaster option; build indexer to mirror events into a PostgreSQL view consumed by the UI.
3. **Week 3:** Add dispute module, commit-reveal flow, and bridge-assisted funding. Run end-to-end flow on zkSync Sepolia; capture gas benchmarks for each action.
