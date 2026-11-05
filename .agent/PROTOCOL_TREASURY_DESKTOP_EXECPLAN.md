# Add reward-account wallet and desktop UX

This living plan follows `.agent/PLANS.md` and extends
`.agent/PROTOCOL_TREASURY_GOVERNANCE_EXECPLAN.md`. Keep Progress, Surprises &
Discoveries, Decision Log and Outcomes & Retrospective current. The user supplied the separate `Pauli-Group/hegemon-website` explorer repository
on 2026-11-05 ET; that work continues on its new `codex/explorer-treasury-rewards`
branch. No merge,
deployment, public-chain reset or production key selection is authorized here.

## Purpose / Big Picture


The desktop wallet should distinguish shielded receiving addresses from public
mining/reward accounts, show pending rewards and their first claim heights, and
explain public treasury donations and quorum-controlled withdrawals. Wallet
creation and recovery should retain the authorization for public accounts using
the existing encrypted root backup. Address entry must check checksum, kind and
exact selected network instead of a hard-coded shca prefix. Amount entry must
retain eight-decimal precision.

A connected legacy node remains usable. Successor screens inspect the real
read APIs and show unsupported/inactive/disconnected states without fictional
balances. Transaction preparation/review can be implemented independently of
native activation; no UI may report a transfer submitted or confirmed unless an
actual supported submission method succeeds. Native admission, synchronization
and submission remain outstanding in the parent protocol plan.

## Progress


- [x] (2026-11-05 ET) Read architecture, methods, branding and the app/walletd
  interfaces; baseline desktop typecheck and 72 tests pass.
- [x] (2026-11-05 ET) Add strict network-aware address and amount helpers and tests.
- [x] (2026-11-05 ET) Add root-derived public account identity and daemon signing/review support,
  with backup/recovery, watch-only and chain-mismatch tests.
- [x] (2026-11-05 ET) Add typed read-only Electron RPC bridge and Rewards & treasury workspace.
- [x] (2026-11-05 ET) Update Receive, Send, Contacts and mining setup without breaking legacy use.
- [x] (2026-11-05 ET) Verify UI rendering, data errors, snapshot/lock races,
  typecheck, production build and focused real-proof Rust checks.
- [ ] Publish and verify commits on the existing branch.

## Surprises & Discoveries


The desktop currently hard-codes shca1 and a single address length, derives
mining payouts from the shielded receive address, and totals mining rewards from
notes. Walletd has no reward-account ownership or review interface. The new
node read APIs exist, but native successor activation and transaction submission
are not installed. A successful UI read is not transaction authority.

## Decision Log


Decision: Derive a versioned per-network ML-DSA account key from the encrypted
wallet root, keeping raw private keys in the daemon. Rationale: existing encrypted
wallet backup and key recovery must reproduce the public account; a separate
unbacked key file would introduce a new loss risk. Watch-only wallets cannot sign.
Date/Author: 2026-11-05 ET, Codex.

Decision: Preserve legacy flows using explicit legacy context, while successor
forms require the selected binary network tag and distinguish public-account
versus shielded-payment addresses. Rationale: both networks coexist before the
operator performs the separately authorized reset.
Date/Author: 2026-11-05 ET, Codex.

Decision: Surface actual operation availability and provide review/export paths
for offline approvals. No method-name guess, checkbox or renderer input may
bypass missing native source authority, spend reservations or real-proof checks.
Date/Author: 2026-11-05 ET, Codex.

## Outcomes & Retrospective


The wallet and desktop UX is implemented: public accounts/epochs, treasury and
supply views, distinct network-aware Receive/mining addresses, exact amounts,
real claim-proof export, donation review, verified offline approvals and separate
key recovery. There is no native successor submission route; donation spend
reservation/proof preparation and activated two-node lifecycle checks remain in
the parent plan. No visual fixture establishes native activation or admission.

Desktop typecheck, 89 tests, production build and UI guards pass. Chromium checks
exercise lock races, malformed/stale snapshots, safe memo rendering, disclosure
reset and password clearing, with overflow-free desktop/mobile screenshots.
Five walletd tests include a genuine payout proof, altered fee/recipient/proof
rejection, partial quorum, duplicate signer and source-preserving recovery checks.
Wallet qualification passes three account/address tests (including real claim
and donation proofs), one deterministic identity/vector test and seventeen
recovery regressions; two unrelated slow recovery tests remain ignored by their
existing defaults. The real walletd stdin create/status/identity smoke also
passes and advertises submission unavailable. The optional macOS launch-autostart
check cannot run here: it requires an existing mac-arm64 packaged `.app`, which
this Linux build does not produce. No deployment or node reset occurred.

## Context and Orientation


Work in /workspace/Hegemon on codex/protocol-treasury-governance. The React UI
is hegemon-app/src/App.tsx with typed Electron bridges in src/env.d.ts and
electron/{preload,main,nodeManager,walletdClient}.ts. Walletd's line-delimited
JSON dispatcher is walletd/src/main.rs. The encrypted wallet root is accessible
only through wallet/src/store.rs; account crypto uses protocol/reward-accounts
and the existing ML-DSA implementation. NetworkShieldedAddress is the typed
wallet wrapper for heg_shield/heg_shield_test. Existing legacy addresses use
Bech32m shca. Public accounts use heg/heg_test.

Reward epoch N releases before transactions in block (N+2)*E+1, with E=1440
for the proposed reset. Genesis allocations are immediately available, reduce
future mining issuance and preserve the 21-million-HGN cap. Available public
balances are distinct from shielded spendable notes. Claims debit amount plus
fee, create a shielded payout, and add no further reward delay. Donation amount
and optional UTF-8 memo are public; implicit subsidy credits have no memo.
Treasury identity is fixed while certified hard forks change its policy and
generation. No public account-to-account payment flow exists.

## Plan of Work


### Milestone 1: address, amount and wallet authority

First implement a small shared TypeScript codec for long Bech32m addresses,
with exact header/type/class/discriminator checks, mixed-case and padding
rejection, and strict decimal atom conversion. Test against Rust-generated
address vectors and all four successor HRPs, including near-miss networks.
Keep legacy handling explicit and preserve original text until its case/checksum
has been validated.

Add deterministic root-derived account identity and public signer policy data
inside wallet/ and walletd/. Use versioned domain separation, index zero for the
default account, and zeroizing secret buffers. Match a bound wallet genesis
before deriving addresses for operations. Reopening a backup reproduces the
same identity; no new wallet schema or private-key export is needed. Add typed
intent review and signing where the owner/quorum policy matches the local key,
with independent expected chain/genesis, signed amount/fee/recipient and digest
confirmation. Never expose raw root seeds through Electron IPC.

### Milestone 2: desktop reads and account operations

Then expose only the four read methods in the Electron main process using its
existing loopback endpoint normalization. Validate response identity, exact
integer strings and conservation in the renderer. Add a dedicated workspace
for owned/public reward lookup, next-block claimability, epoch release buckets,
initial genesis allocations, treasury donation review and current/pending
quorum policy. Empty, unsupported, inactive, stale and disconnected states must
be visibly different. Clear private/reviewed state on lock, endpoint changes or
changed inputs, and ignore late requests from an old wallet/network.

Update the app's existing receiving/copy, send/contact validation and miner
configuration to use the selected network and address kind. Keep shielded note
balances distinct from account balances and prevent reusing a receiving address
as a public mining destination. Display exact HGN amounts and explicit public
memo disclosure. Use existing brand tokens, responsive cards, accessible labels
and text rendering for node-provided strings. The UI cannot add a general public
send or silently reinterpret legacy addresses on the successor network.

### Milestone 3: qualification and publication

Finally exercise all ordinary legacy operations and capability-gated successor
views with tests and a browser render. Actual account claims/donations on two
nodes remain dependent on the parent canonical/native submission work. Record
that limitation in the UI and final result without claiming payment completion.

## Concrete Steps


Load /workspace/toolchains/env.sh for Rust and Node tooling. From hegemon-app/,
run npm ci, npm run typecheck, npm test, npm run build and npm run check:ui-guards.
Run focused wallet/walletd tests for the new identity/review and malformed-input
boundaries. Use scoped rustfmt and git diff --check. Keep browser artifacts and
build logs in /workspace/work, outside Git. Use no production wallet material.

## Validation and Acceptance


Accept correct heg/heg_test and heg_shield/heg_shield_test addresses only for
their selected network and operation. Reject rechecksummed HRP relabeling,
different discriminators, mixed case, incorrect padding/checksums and public
addresses in normal payment fields. Preserve valid uppercase entry until it is
validated, then canonicalize. No decimal amount may round silently or accept
negative, exponent, partial numeric or over-eight-decimal input.

Show available/pending accounts and first-claim height separately from shielded
notes. At h2880 with E1440, epoch-zero rewards remain pending and become
claimable at h2881. Warn that epoch boundaries are not finality. A restored
wallet reproduces the same public account on the same network and a distinct
one on a different discriminator. Watch-only and wrong-genesis signing fail.
Intent mutations, missing/mismatched policies and unapproved digests reject.
Read errors cannot turn into a valid zero balance. Test stale response races,
lock/reset state clearing, exact root/amount strings, public memo rendering and
long address copy/wrap. Transaction buttons must never fabricate success when
native submission or proof/reservation support is unavailable.

## Idempotence and Recovery


Do not migrate live databases or silently reset wallet scans. Retain legacy
contacts/addresses as legacy data and require correct network selection on
new operations. Derivation uses the existing encrypted root; it writes no raw
private key or secret to a node, renderer, logs or Git. Review/approval artifacts
contain public intent and signatures only. Claim or donation retries require
canonical sequence and inclusion reconciliation in the parent native workflow.

## Artifacts and Notes


Baseline: desktop typecheck succeeds and all 72 existing tests pass. Completed
results are recorded above; commands are reproducible in
`docs/PROTOCOL_TREASURY_WALLET_UX.md`. Local logs are under
`/workspace/work/environment-setup/reward-ux-*`, and inspected screenshots are
`/workspace/work/reward-ux/{desktop,mobile}.png` (explicit fixtures only).

The browser harness binds only loopback and has no production activation or
submission path. It cleans temporary pages/profiles. The wallet's fixed public
address vectors are checked by Rust and TypeScript from the same JSON fixture.

## Interfaces and Dependencies


Prefer the existing React, Electron, serde, codec, ML-DSA and protocol account
crates. Add no proof authority, public-chain runtime flag or alternate explorer.
New desktop RPC bridge accepts a closed read-method union. Walletd reward
methods operate only on an unlocked full wallet for signatures, with explicit
network/genesis context and digest confirmation. All monetary, root-word,
epoch and sequence values from the new public APIs remain decimal strings.

Revision note (2026-11-05 ET): implement the user's requested desktop/wallet UX
scope while preserving the separate explorer and native activation
requirements.
