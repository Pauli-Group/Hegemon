# User Privacy Guidelines

These guidelines explain how to use HEGEMON (HGN) software in a way that preserves the post-quantum privacy guarantees described in `README.md`, `DESIGN.md`, `METHODS.md`, and `docs/THREAT_MODEL.md`. Treat this document as the living owner’s manual for privacy hygiene: every new wallet feature, networking mode, or governance control must be reflected here so that end users can make informed operational decisions.

## 1. Purpose and scope
- **Audience** – Wallet operators, PoW miners, governance participants, and auditors who interact with HGN infrastructure or artifacts derived from it.
- **Goals** – Minimize metadata leakage, protect secret material, and keep shielded transactions unlinkable even when an adversary controls networks or compromised devices as described in the threat model.
- **Maintenance rule** – Any change to shielded-pool semantics, wallet key handling, networking transports, or disclosure tooling must update these guidelines before the feature is considered shippable.

## 2. Core principles
1. **Local custody first** – Generate and store spending/view keys only inside wallets you control. Never paste keys into remote tooling.
2. **Version parity** – Use the same release channel for wallet, consensus, and governance clients so that circuit bindings and privacy patches land simultaneously.
3. **Least disclosure** – Share selective-disclosure proofs or decrypted memos only with entities that can prove a regulatory or contractual requirement.
4. **Documented workflows** – Follow the official runbooks (e.g., `runbooks/security_testing.md`) whenever a security workflow or audit is triggered; ad-hoc steps often leak metadata.

## 3. Wallet hygiene checklist
| Phase | Required actions |
| --- | --- |
| Provisioning | Verify signatures for `wallet/` binaries, run `make wallet-demo` on an air-gapped machine to inspect note/memo handling, and create wallets inside full-disk encrypted storage. |
| Key management | Generate spend/view keys offline, record mnemonic backups using Shamir or multi-location sealed envelopes, and rotate viewing keys every time a new auditor is added. |
| Daily use | Sync via shielded RPC calls only, disable analytics/telemetry on the host OS, and randomize transaction batching (wallet CLI flag `--randomize-memo-order`) to avoid deterministic memo ordering. |
| Recovery | When restoring from mnemonic, re-run the wallet adversarial tests referenced in `runbooks/security_testing.md` and rotate nullifier-derivation salts so compromised backups cannot track new notes. |

Additional wallet-specific recommendations:
- Pin the `VersionSchedule` hash emitted by your consensus peers before crafting a transaction so you do not build proofs against deprecated circuits.
- Use the wallet’s built-in address book tags instead of plaintext memos when referencing counterparties; tags stay local and prevent memo correlation.
- Enable `wallet send --randomize-memo-order` (or set the flag in wrapper scripts) before the public alpha launch so deterministic memo ordering never reveals which recipients were co-batched in a shielded transaction.
- Never re-use transparent fallback addresses when shielded notes are available. Transparent outputs should remain disabled unless governance explicitly mandates an escape hatch.

## 4. Node and network hygiene
- **Run your own light/full node** – Point wallets at self-hosted RPC endpoints hardened with TLS and mutual authentication. Shared endpoints can log note commitment deltas.
- **Network privacy layers** – Route RPC and gossip traffic through mixnets, Tor, or VPNs that do not share exit IPs with personal browsing. Monitor bandwidth padding in `consensus/bench` to ensure timing obfuscation stays enabled.
- **Log discipline** – Sanitize or disable disk logs that contain nullifiers, note commitments, IPs, or governance votes. If logs must be retained for compliance, encrypt them with ML-KEM session keys and rotate every epoch.
- **Software updates** – Subscribe to release feeds and apply critical patches (especially ones touching `crypto/` or `wallet/`) within 24 hours. Always restart both wallet and node processes so that patched privacy parameters take effect.

## 5. Crafting private transactions
1. **Fresh addresses per counterparty** – Use diversified addresses for each relationship; the wallet CLI’s `addr new --purpose shielded` command keeps derivations deterministic without re-use.
2. **Value obfuscation** – When protocol fees allow, split large payments into randomized shards executed over multiple blocks to defeat value correlation.
3. **Memo discipline** – Prefer encrypted memos with structured data fields (recipient, invoice hash, compliance tag). Avoid free-form text that could leak identity clues.
4. **Timing randomness** – Introduce randomized delays (1–30 minutes) between proof generation and broadcast to prevent timing correlation with real-world events.
5. **Selective disclosure** – When an auditor requires insight, export view keys scoped to specific accounts and expiration heights rather than the global wallet view key.

## 6. Device, supply-chain, and physical security
- Use hardware with verified boot and keep firmware hashes recorded in an operator log.
- Dedicate machines (or VMs) to HGN operations so browsing, messaging, and wallet activity do not share memory space.
- Keep air-gapped builders for proving key generation or for running `circuits/formal` verification jobs; never copy proving keys through untrusted cloud storage.
- Store mnemonic backups in tamper-evident bags and implement dual-control (two people present) before any recovery attempt.

## 7. Incident handling and reporting
1. **Detect** – Monitor wallet logs for unexpected nullifier rejections, sudden increases in RPC errors, or version-mismatch warnings.
2. **Contain** – Immediately revoke viewing keys shared with third parties, rotate RPC credentials, and stop broadcasting transactions until the issue is understood.
3. **Eradicate** – Follow `runbooks/emergency_version_swap.md` if a circuit binding is compromised, and deploy patched binaries from the trusted release channel.
4. **Recover** – Rescan the chain from a known-good height, regenerate diversified addresses, and inform affected counterparties via encrypted channels.
5. **Report** – File an incident entry in `docs/SECURITY_REVIEWS.md` (or the external tracker) that references the affected functions, proofs, and mitigations so the broader ecosystem can verify the response.

## 8. Update cadence and ownership
- **On every release candidate** – Review this document alongside `DESIGN.md` and `METHODS.md`; confirm that new bindings, disclosure options, or wallet UX changes have corresponding privacy steps.
- **After every security review** – When `docs/SECURITY_REVIEWS.md` gains a new entry, update this guide with any new mitigations or workflow changes.
- **Quarterly privacy drills** – Operators should rehearse the checklist in Sections 3–7, capture deviations, and open issues if tooling cannot enforce a recommendation.
- **Document stewardship** – The wallet team owns Sections 3 & 5, the consensus/networking team owns Section 4, and the governance team owns Sections 6–8. Ownership must be reassigned explicitly whenever team composition changes.

Keeping this guide synchronized with implementation details ensures HGN’s privacy guarantees remain actionable rather than aspirational. Treat every guideline as a testable requirement, and open a pull request whenever you find a gap.
