# User Privacy Guidelines

These guidelines explain how to use HEGEMON (HGN) software in a way that preserves the post-quantum privacy guarantees described in `README.md`, `DESIGN.md`, `METHODS.md`, and `docs/THREAT_MODEL.md`. Treat this document as the living owner’s manual for privacy hygiene: every new wallet feature, networking mode, or protocol-control surface must be reflected here so that end users can make informed operational decisions.

## 1. Purpose and scope
- **Audience** – Wallet operators, PoW miners, release operators, and anyone who receives exported viewing keys or wallet records.
- **Goals** – Minimize metadata leakage, protect secret material, and keep shielded transactions unlinkable even when an adversary controls networks or compromised devices as described in the threat model.
- **Maintenance rule** – Any change to shielded-pool semantics, wallet key handling, networking transports, or disclosure tooling must update these guidelines before the feature is considered shippable.

## 2. Core principles
1. **Local custody first** – Generate and store spending/view keys only inside wallets you control. Never paste keys into remote tooling.
2. **Version parity** – Use the same release channel for wallet, consensus, and release artifacts so that circuit bindings and privacy patches land simultaneously.
3. **Least disclosure** – Share decrypted memos or viewing keys only when a counterparty or verifier needs them. The current wallet has no cryptographic account/height-scoped viewing-key format.
4. **Documented workflows** – Follow the official runbooks (e.g., `runbooks/security_testing.md`) whenever a security workflow or audit is triggered; ad-hoc steps often leak metadata.

## 3. Wallet hygiene checklist
| Phase | Required actions |
| --- | --- |
| Provisioning | Verify signatures for `wallet/` binaries, run `make wallet-demo` on an air-gapped machine to inspect note/memo handling, and create wallets inside full-disk encrypted storage. |
| Key management | Generate spend/view keys offline, protect mnemonic backups in separate secure locations, and use a separate wallet/account when a disclosure recipient must not see unrelated activity. |
| Daily use | Prefer a self-hosted node over loopback or an operator-managed authenticated tunnel, and disable unrelated host analytics or telemetry. |
| Recovery | Restore only on a trusted host, rescan from a known checkpoint, and treat any previously exposed viewing key as permanently able to inspect the history it covers. |

Additional wallet-specific recommendations:
- Keep wallet and node versions aligned so proof bindings and parser fixes change together.
- Keep counterparty labels outside encrypted on-chain memos unless the recipient needs them.
- Never re-use transparent fallback addresses when shielded notes are available. Transparent outputs should remain disabled.
- Targeted disclosure proof creation and verification are unavailable in the SmallWood-only release. Do not treat outgoing wallet records as cryptographic receipts.
- Use `wallet payment-proof purge` when an outgoing disclosure record reaches the end of its local retention window.

## 4. Node and network hygiene
- **Run your own node** – Prefer loopback RPC to a self-hosted node. If remote access is required, place the plaintext node RPC behind an operator-managed authenticated tunnel or reverse proxy; the wallet does not add TLS itself.
- **Network privacy layers** – Hegemon does not currently provide built-in Tor, mixnet, cover traffic, or timing padding. Operators may add an external privacy transport, but must not describe it as a protocol guarantee.
- **Log discipline** – Sanitize or disable disk logs that contain nullifiers, note commitments, IPs, or release-operator activity. Protect retained logs with normal host access controls and encrypted storage.
- **Software updates** – Subscribe to release feeds and apply critical patches (especially ones touching `crypto/` or `wallet/`) within 24 hours. Always restart both wallet and node processes so that patched privacy parameters take effect.

## 5. Crafting private transactions
1. **Fresh addresses per counterparty** – Derive a fresh diversified address for each relationship and avoid address reuse.
2. **Value obfuscation** – When protocol fees allow, split large payments into randomized shards executed over multiple blocks to defeat value correlation.
3. **Memo discipline** – Prefer encrypted memos with structured data fields (recipient, invoice hash, proof tag). Avoid free-form text that could leak identity clues.
4. **Timing randomness** – Introduce randomized delays (1–30 minutes) between proof generation and broadcast to prevent timing correlation with real-world events.
5. **Disclosure boundary** – The current export is an incoming or full viewing key, not a cryptographically scoped key. Use a separately derived wallet/account for future limited disclosure and treat an exported existing key as exposing its full supported history.

## 6. Device, supply-chain, and physical security
- Use hardware with verified boot and keep firmware hashes recorded in an operator log.
- Dedicate machines (or VMs) to HGN operations so browsing, messaging, and wallet activity do not share memory space.
- Keep air-gapped builders for proving key generation or for running `circuits/formal` verification jobs; never copy proving keys through untrusted cloud storage.
- Store mnemonic backups in tamper-evident bags and implement dual-control (two people present) before any recovery attempt.

## 7. Incident handling and reporting
1. **Detect** – Monitor wallet logs for unexpected nullifier rejections, sudden increases in RPC errors, or version-mismatch warnings.
2. **Contain** – Viewing keys are not revocable. Rotate RPC credentials, stop broadcasting until the issue is understood, and move future activity to a fresh wallet/account when a viewing key has been exposed.
3. **Eradicate** – Follow `runbooks/emergency_version_swap.md` if a circuit binding is compromised, and deploy patched binaries from the trusted release channel.
4. **Recover** – Rescan the chain from a known-good height, regenerate diversified addresses, and inform affected counterparties via encrypted channels.
5. **Report** – File an incident entry in `docs/SECURITY_REVIEWS.md` (or the external tracker) that references the affected functions, proofs, and mitigations so the broader ecosystem can verify the response.

## 8. Update cadence and ownership
- **On every release candidate** – Review this document alongside `DESIGN.md` and `METHODS.md`; confirm that new bindings, disclosure options, or wallet UX changes have corresponding privacy steps.
- **After every security review** – When `docs/SECURITY_REVIEWS.md` gains a new entry, update this guide with any new mitigations or workflow changes.
- **Quarterly privacy drills** – Operators should rehearse the checklist in Sections 3–7, capture deviations, and open issues if tooling cannot enforce a recommendation.
- **Document stewardship** – The wallet team owns Sections 3 & 5, the consensus/networking team owns Section 4, and the protocol/release team owns Sections 6–8. Ownership must be reassigned explicitly whenever team composition changes.

Keeping this guide synchronized with implementation details ensures HGN’s privacy guarantees remain actionable rather than aspirational. Treat every guideline as a testable requirement, and open a pull request whenever you find a gap.
