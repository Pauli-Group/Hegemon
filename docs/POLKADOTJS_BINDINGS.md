# Polkadot.js bindings for the proof-native runtime

Polkadot.js can still connect to the node for chain/state inspection, metadata browsing, and manual RPC experimentation. It should not be treated as the supported transaction-submission interface, because the live chain no longer exposes a normal account/extrinsic lane.

## What Polkadot.js is still good for

- browsing blocks and headers
- inspecting runtime metadata
- reading storage through `state_*`
- checking node/network status through `system_*`

## What it should not be used for

- submitting ordinary signed transactions
- assuming a balances pallet exists
- interacting with settlement, archive-market, treasury, or feature-flag pallets that are no longer part of the live runtime

## Runtime focus

The live runtime centers on:

- `ShieldedPool`
- `Difficulty`
- the local PoW support pallet
- `System` and `Timestamp`

If you need to submit a protocol action, use the Hegemon RPC method:

- `hegemon_submitAction`

`hegemon_submitShieldedTransfer` remains only as a deprecated shielded-send adapter. Do not treat either as a generic account-based extrinsic path.
