# v0.11 pre-mainnet operator guide

**Status: prepared for review; public cutover pending.** Keep the existing
v0.10.3 service on `hegemon-ovh` running until the operator announces shutdown.
No command below is an instruction to perform cutover now.

`network-manifest.json` fixes the public network parameters. `release.json`
binds its SHA-256 digest, release name, network and approved seed list. The
launcher refuses a pending record. Marking a reviewed release ready is an
operator packaging step, not an expiry height or a lifetime transaction limit.
This release imposes neither of those limits on the blockchain.

## Identity and custody

- Release/display/tag: **v0.11**; product/app version: **0.11.0**. Internal
  Cargo package versions remain source-bound at their qualified values; changing
  those changes the proof identity. The node RPC and wallet CLI report 0.11.0.
- Network: **pre-mainnet**, fresh genesis distinct from the v0.10.3 chain and
  private qualification rehearsals. Never reinterpret either chain's old state
  or proofs under the new identity.
- Planned primary seed: `hegemon.pauli.group:30333` (`hegemon-ovh`).
  `hegemon-dev` becomes secondary after both hosts pass cutover checks.
  Read the exact seed list from the final release record.
- Existing single-key treasury recipient remains the approved wallet. Preserve
  its encrypted backup and restore rehearsal. A reset does not change key
  ownership, and old chain balances do not migrate automatically.
- Every miner must receive rewards at a user-controlled full public address.
  A mining server only needs that public recipient; it does not need a spending
  key. Store treasury/spending credentials outside the node and repository.
- Native HGN only; stablecoins and AuxPoW/merge mining stay disabled. Miner and
  treasury rewards mature after **120 blocks**. Keep NTP/chrony synchronized.

## Start a syncing node after cutover

Verify the published release hashes and network record before installing the
matching binary. From the release source checkout, with the verified node at
`target/release/hegemon-node`:

```bash
./start.sh
```

This uses `--network pre-mainnet`, the versioned manifest, loopback safe RPC on
port 9944 and the separate `~/.hegemon-node-v0.11` state directory. It does not
use `--dev`, enable mining, reset an existing directory or open a wallet.
`HEGEMON_NODE_BIN` can select a separately installed, verified binary;
`HEGEMON_NODE_PATH` can select a deliberate v0.11 data directory. Do not point
it to an old chain database. The optional local node is sync-only.

## Start an explicitly selected miner after cutover

The first OVH bootstrap is a separate operator runbook step; the public launcher
is for joining the running network. Use your own full reward address:

```bash
HEGEMON_MINE=1 HEGEMON_MINER_ADDRESS='<your-full-public-address>' ./start.sh
```

The launcher uses the final release seed list and rejects a different inherited
`HEGEMON_SEEDS` value. It requires mining to be exactly 0 or 1. The node validates
the address and network/proof authority. No key is generated or copied to the
server. Do not use the old interactive mining helper for this launch.

## Cutover acceptance

After the operator's shutdown announcement: retain old data/configuration;
install the exact approved artifacts on OVH and dev into fresh state paths;
verify manifest/genesis/chain/rules digests on both; confirm NTP, peer connection,
mining and common canonical block hashes; then optionally sync a fresh local
node without mining. Check reward recipients against the user's chosen public
address. Open Discord onboarding only after these checks and the final published
release/install instructions agree. See the [release checklist](../../../docs/releases/v0.11.md).
