# Hegemon Testnet Deployment

The public test network is **v0.11 pre-mainnet**, running from a fresh genesis.
Use the [v0.11 joining guide](0.11/README.md) and
[v0.11 release](https://github.com/Pauli-Group/Hegemon/releases/tag/v0.11).
For source builds, check out **tag `v0.11`**. Mainnet will use a separate `v1.00`
launch; v0.10.3 balances and databases do not migrate.

**The software version alone does not select the public chain.** A bare
`hegemon-node` defaults to the legacy profile, and `--dev` does not join public
v0.11. Use `./start.sh` from the tagged source checkout, or `python3 start.py`
from an extracted release package. These launchers select `--network pre-mainnet`
and `config/testnet/0.11/network-manifest.json` explicitly. Setting seed addresses
alone cannot change network identity.

The primary seed is `hegemon.pauli.group:30333` (`hegemon-ovh`); the secondary is
`devnet.hegemonprotocol.com:30333` (`hegemon-dev`). The launchers use this approved
list from `0.11/release.json`. Keep NTP/chrony or automatic time sync enabled:
PoW headers outside the allowed future timestamp skew are rejected.

Before mining, verify genesis:
`0xd9a8cfc158790b0251c7493d7261da771f7d57be63bce750ba8c1af5d92a9ad3`.
The joining guide includes the RPC commands and expected chain ID. Peer count
alone is not proof that you joined the correct chain.

If genesis differs or all peers remain at height zero, stop the node cleanly,
preserve its data and wallet, and use a new, unused data directory with the
correct launcher. Do not mine block 1 on a different chain or delete an existing
database to repair a configuration mistake. The launcher defaults to sync/relay;
mining is opt-in and requires your own full public reward address.

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
