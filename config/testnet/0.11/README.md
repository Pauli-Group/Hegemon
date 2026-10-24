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
  Cargo package versions remain unchanged; the node RPC and wallet CLI report
  0.11.0. Four security dependency updates changed `Cargo.lock` and the proof
  identity. Current proof checks and the H0 build pass; final current-artifact
  and lifecycle authorization remain pending. Reused evidence keeps its original
  source and artifact identity.
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

## Wallet and app qualification scope

The v0.11 bundle contains the native node, wallet CLI and walletd. The app CI
check exercises a real mining seed, P2P relay and fresh-wallet synchronization
over loopback RPC with zero funds. Its result explicitly reports
`fundedTransactionsExercised:false`; it does not qualify funded desktop-wallet
sends, consolidation or private multisig. The older GUI flow uses a retired
mint/spend route and its legacy primary address is not a v0.11 mining recipient.
Use a full V8 recipient created by the separately qualified native wallet tooling.

Native HGN spending, HTLCs and 120-block miner/treasury maturity retain their
source-authorized lifecycle evidence. Final platform artifacts must still pass
their required source/identity, proof/H0 and binary security checks. App sync
success does not replace those gates or authorize cutover.

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

## Use the packaged common HGN private-spend CLI

The four platform bundles include `private-spend` with the node, wallet and
wallet daemon. Verify its published SHA-256 checksum before installing the
matching platform binary as `private-spend` (`private-spend.exe` on Windows).
`private-spend --version` reports the release version. Its standalone
`--print-crypto-profile` command is the existing offline legacy-profile
diagnostic and retains that diagnostic's fail-closed refusal; it does not attest
the current PrivateSpend relation. Network commands verify the supplied manifest
and genesis against the node and require the separate source-owned
private-spend authority. Identify installed files by the release manifest and
binary checksum.

After the final release and network are approved, use the verified loopback RPC
and an encrypted wallet whose notes have been synced on that exact network:

```bash
./private-spend --wallet '<encrypted-wallet>' \
  --manifest config/testnet/0.11/network-manifest.json \
  --genesis '<approved-genesis-hash>' --rpc http://127.0.0.1:9944 notes
./private-spend --wallet '<encrypted-wallet>' \
  --manifest config/testnet/0.11/network-manifest.json \
  --genesis '<approved-genesis-hash>' --rpc http://127.0.0.1:9944 \
  ordinary --inputs '<note-position>' --recipient '<full-private-spend-address>' \
  --amount '<integer-HGN-atoms>' --fee '<integer-HGN-atoms>'
./private-spend --wallet '<encrypted-wallet>' \
  --manifest config/testnet/0.11/network-manifest.json \
  --genesis '<approved-genesis-hash>' --rpc http://127.0.0.1:9944 \
  submit '<retained-attempt-id>'
```

`ordinary` retains the exact prepared attempt in the encrypted wallet; submit
that retained identifier. The packaged production build enables `rpc-client`
and omits development artifacts. Existing native proof, H0, lifecycle and
security qualification remain mandatory before release authorization.

## Cutover acceptance

After the operator's shutdown announcement: retain old data/configuration;
install the exact approved artifacts on OVH and dev into fresh state paths;
verify manifest/genesis/chain/rules digests on both; confirm NTP, peer connection,
mining and common canonical block hashes; then optionally sync a fresh local
node without mining. Check reward recipients against the user's chosen public
address. Open Discord onboarding only after these checks and the final published
release/install instructions agree. See the [release checklist](../../../docs/releases/v0.11.md).
