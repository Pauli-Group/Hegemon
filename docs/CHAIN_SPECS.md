# Chain specification guide

This guide tracks the chain specifications we ship for coordinated testing and pre-mainnet rehearsals. Each spec lists the bootstrapping keys required to finalize genesis.

## Testnet0
- **Goal:** Single-validator smoke tests for block production, PoW/PoS hand-off plumbing, and dashboard telemetry.
- **Genesis authorities:**
  - Aura/Grandpa: development key derived from `//Alice` (replace with hardware-backed authority before external distribution).
- **Bootstrapping keys:** Bundle a faucet account seeded with 10^12 units and expose its mnemonic only in the internal secrets vault. Preload observability keys so `pallet-observability` emits metrics immediately.
- **Governance note:** No council/technical committee seats are seeded in this spec.

## Testnet1
- **Goal:** Multi-validator adversarial testing (latency, equivocation handling, oracles).
- **Genesis authorities:**
  - Aura/Grandpa: 3 validators backed by HSM-derived sr25519 keys (``//Validator0``, ``//Validator1``, ``//Validator2`` derivations stored in vault).
- **Bootstrapping keys:**
  - Faucet split into three 10^11 tranches controlled by separate operators.
  - Oracle operators: pre-register feed keys for FX and rates pallets, pinned in `pallet-oracles` genesis config.
- **Governance note:** No council/technical committee seats are seeded in this spec.

## Testnet2
- **Goal:** Governance cadence, fee-model rehearsals, and end-to-end wallet flows with real exchanges.
- **Genesis authorities:**
  - Aura/Grandpa: 5 validators (mix of HSM + YubiHSM), keys escrowed in the shared custody vault with change-control tickets.
- **Bootstrapping keys:**
  - Treasury multisig: 3-of-5 accounts funded from genesis with 10^11 units each; include the treasury stash address in the spec to pre-fund fee subsidies.
  - Settlement verifier keys: populate `pallet-settlement` with the default verification key and STARK parameters matching Testnet2 constraints.
- **Governance note:** No council/technical committee seats are seeded in this spec.

## Pre-mainnet (candidate)
- **Goal:** Dress rehearsal for mainnet launch with governance, treasury, and observability mirrors of production.
- **Genesis authorities:**
  - Aura/Grandpa: 7 validators (2 security team, 5 community), each with backup keys sealed in tamper-evident HSM exports.
- **Bootstrapping keys:**
  - Faucet removed; genesis allocations sent to custodial wallets and fee-relayer accounts only.
  - Oracle and settlement verifier keys registered with rotation schedules and on-chain expirations.
  - Observability: inject Prometheus/Grafana endpoints in the spec and pre-approve WebSocket telemetry signing keys.
- **Governance note:** No council/technical committee seats are seeded in this spec.

## Authoring notes
- Keep these specs synchronized with `DESIGN.md` network parameters and the governance procedures in `METHODS.md`.
- When generating JSON specs, commit the signed authority keys to the internal registry and link the digest here.
- Include the expected `spec_version` and `state_version` bumps in release notes so node operators can validate binaries before joining.
- Any protocol-breaking commitment/nullifier encoding change (e.g., switching to 6-limb 384-bit encodings) requires operators to delete `node.db` and wallet store files before joining the new chain spec.
