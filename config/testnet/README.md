# Hegemon Testnet Deployment

The next public testnet is **v0.11 pre-mainnet**, starting from fresh genesis.
Use the [v0.11 operator guide](0.11/README.md) and
[release checklist](../../docs/releases/v0.11.md). The release tag/display name is
`v0.11`; executable package versions are `0.11.0`. Mainnet is planned as `v1.00`.

**Cutover is pending.** The v0.10.3 testnet on `hegemon-ovh` must remain running
until the operator announces its shutdown. Preparing a PR or building v0.11
artifacts does not change the live network. Do not join the existing seed with
the new manifest or replace the old database in place.

For v0.11, `hegemon.pauli.group:30333` (`hegemon-ovh`) is the planned primary
seed. `hegemon-dev` is a secondary node after cutover. The exact approved seed
list comes from `0.11/release.json`; local defaults do not establish live
approval. Keep every miner on the same approved list and enable NTP/chrony:
PoW headers outside the allowed future timestamp skew are rejected.

The source launcher `../../start.sh` validates the versioned manifest digest,
refuses a pending release record and defaults to a syncing node with a separate
`~/.hegemon-node-v0.11` database. Mining is opt-in and requires the operator's
public reward address. It never creates or deletes a wallet.

## Pool interfaces

Follow the [pool interface contract](../../docs/POOL_INTERFACES.md). Select the
approved release, genesis, chain/rules and full public pool payout recipient
before requesting work. The node supplies mining interfaces; share accounting
and pool operation remain the pool operator's responsibility.

Use `--rpc-methods=pool` on loopback. Forward it through authenticated SSH or an
existing authenticated gateway if remote access is needed; do not expose unsafe
RPC publicly. The method allowlist is not caller authentication. Keep spending
credentials and payout submission on a separate wallet control plane.

`hegemon_blockReward` returns canonical reward observations with decimal
`*_atoms` strings and public recipient bindings. Miner and treasury rewards
created in block `h` first permit spending in block `h + 120`. Extra payout
confirmations/reserves are operator policy. Reconcile orphaned rewards before
crediting miners; confirmations do not establish deterministic finality.
Stablecoin infrastructure and merge mining remain disabled for this release.

## Historical deployment material

The v0.10.3 database, service configuration and wallets are historical state.
Preserve them through cutover. Legacy Docker instructions, `--dev` startup and
`scripts/start-mining.sh` are not the v0.11 public join procedure. A fresh chain
changes balances and network identity; it does not require changing the existing
treasury wallet key. No private wallet material belongs in a release or Git.
