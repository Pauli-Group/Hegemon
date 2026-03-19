# Chain specification guide

This guide tracks the chain-spec assumptions we ship after the proof-native cut. The live runtime is a PoW shielded chain with no public balance pallet, no treasury, and no account-funded bootstrap lane. A valid chain spec should therefore describe mining, networking, and protocol defaults, not pre-funded accounts or governance seats.

## Shared rules

Every shipped spec should follow these rules:

- no `balances` genesis section
- shielded-pool defaults come from `runtime::manifest::ProtocolManifest`
- version schedules and proof defaults are release artifacts, not ad-hoc JSON knobs
- operators must share the same approved `HEGEMON_SEEDS` list to avoid forks
- operators must keep NTP/chrony enabled because PoW timestamps are future-skew bounded

## Dev / local spec

Purpose:
- quick local mining and wallet testing
- temporary databases and resettable state

Expected behavior:
- no public allocations at genesis
- shielded coinbase is the only issuance path
- standard chain/state/system RPC is available for inspection
- Hegemon RPC is the supported submission surface

## Testnet spec

Purpose:
- multi-node mining tests
- sync and proof-availability rehearsals
- wallet interoperability and version-schedule rollout drills

Expected content:
- bootnode and seed configuration
- PQ network identity material
- difficulty defaults
- shielded-pool verifying key and fee/policy defaults derived from the protocol manifest
- any version schedule changes required for the testnet release

What not to include:
- treasury multisigs
- faucet accounts funded from genesis
- settlement or archive-market genesis configuration
- feature-flag or observability rollout state

## Authoring notes

- Keep chain-spec JSON synchronized with `runtime/src/manifest.rs`, `runtime/src/chain_spec.rs`, and `node/src/substrate/chain_spec.rs`.
- If protocol defaults change, regenerate the chain spec from the new release build rather than editing old JSON by hand.
- Treat chain specs as release artifacts for a fresh network. Do not assume in-place migration from an older account-based dev chain.
- When documenting testnet setup, always publish the exact approved `HEGEMON_SEEDS` list and remind miners to use the same list.
