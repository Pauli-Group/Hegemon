# Join the v0.11 pre-mainnet

v0.11 is the fresh HGN-only pre-mainnet test network. It replaces v0.10.3;
old balances and proofs do not migrate. Mainnet will use a separate v1.00
launch and identity. Preserve old node data and wallet backups.

## Select the public chain first

Use **tag `v0.11`** for source builds, or the platform archives from that release.
The tag is `da7be324`; older source links to `9e580878` predate the final joining
package. They do not identify a different public chain.

**Building v0.11 does not select pre-mainnet automatically.** A bare
`hegemon-node` defaults to the legacy profile. `--dev` and `--network development`
select other chains; seed addresses alone never select a network. The public
launch must include `--network pre-mainnet` and this release's frozen
`--network-manifest`. The launchers below supply both, so use them instead of
older testnet or development commands.

Stop any existing local node before taking port 9944, so the identity checks
query the node you just started. Start in sync/relay mode and verify the full
genesis and chain ID below before enabling mining. If the genesis differs,
preserve the existing database and wallet and select a new, unused data path.
Do not mine a separate block 1 or delete old state.

## Install the release package

Download the archive for your platform from the
[v0.11 release](https://github.com/Pauli-Group/Hegemon/releases/tag/v0.11),
compare its SHA-256 checksum with the published release checksums, then extract
it to a new directory. The packages contain `bin/` executables, launchers and
`config/testnet/0.11/`. Run the following commands from that extracted directory.
Python 3 is required for the launcher's release-metadata checks. On Linux and
macOS, make sure `bin/hegemon-node` is executable. The examples use `start.py`;
`./start.sh` and Windows `start.cmd` are convenience wrappers.

The bundle's product version is **0.11.0**; the release/tag is **v0.11**. Internal Cargo package
versions are unchanged. The four platform packages reuse the 16 qualified
binaries; they are not rebuilt by the final metadata and launcher update.
Each archive includes `SHA256SUMS` for its contents and `bundle.json` for package
provenance. Its `provenance/hegemon-release-assets-<platform>.json` preserves the
original binary artifact manifest. The recorded binary source commit is
`46895bf8734ccedf1e7b31c44a43b9a7212597fc`, tree
`3bfa87d491879734c0f1b69bea65fa374aad3c77`. Preserve the included artifact
manifests. The packaging source commit in `bundle.json` identifies the newer
release metadata and launchers separately from that binary provenance.

## Network identity

| Item | Required value |
| --- | --- |
| Network | `pre-mainnet` |
| Manifest SHA-256 | `386f21b8d9b474fce096c0691ec7d625f292e9aadf0cd5f06fb4088442ec6754` |
| Genesis | `0xd9a8cfc158790b0251c7493d7261da771f7d57be63bce750ba8c1af5d92a9ad3` |
| Chain ID | `0x7b7b0899d5444ffd92c38b38188e9ce4f891913ca7cca854fdcae0aa22ca1b49` |
| Primary seed | `hegemon.pauli.group:30333` (`hegemon-ovh`) |
| Secondary seed | `devnet.hegemonprotocol.com:30333` (`hegemon-dev`) |

`release.json` binds the frozen manifest and approved seed list to this deployed
identity. Keep NTP/chrony or your operating system's automatic time sync enabled:
blocks too far in the future are rejected. All miners must use the same seeds
to avoid partitions and forks:

```bash
export HEGEMON_SEEDS="hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333"
```

The launcher uses that list automatically and rejects a conflicting inherited
`HEGEMON_SEEDS`. Native HGN is enabled; stablecoin infrastructure and
AuxPoW/merge mining are disabled. Miner and treasury rewards created at height
`h` first become spendable in block `h + 120`. The single-key treasury recipient
remains the approved address in the frozen manifest, receiving 20% of the block
subsidy. There is no arbitrary expiry height or lifetime transaction quota.

## Start a syncing relay

Linux or macOS:

```bash
HEGEMON_MINE=0 HEGEMON_MINER_ADDRESS= python3 start.py
```

Windows PowerShell:

```powershell
$env:HEGEMON_MINE = "0"
$env:HEGEMON_MINER_ADDRESS = ""
py -3 start.py
```

The default role is sync/relay. The launcher selects `--network pre-mainnet`,
checks the release metadata and manifest, keeps safe RPC on loopback port 9944,
and uses the separate `~/.hegemon-node-v0.11` data directory. It does not reset
an existing directory or create a wallet. Do not point `HEGEMON_NODE_PATH` at a
v0.10.3 database. Use `--data-dir '<fresh-v0.11-directory>'` to select a different
state path. The package launcher uses `bin/hegemon-node` (`.exe` on Windows).
From a source checkout, `./start.sh` uses `target/release/hegemon-node`; the
extracted package uses its own `start.py`.

In another terminal, check the running node's identity. On Linux or macOS:

```bash
curl -s http://127.0.0.1:9944 -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"chain_getBlockHash","params":[0]}'
curl -s http://127.0.0.1:9944 -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":2,"method":"hegemon_nodeConfig","params":[]}'
curl -s http://127.0.0.1:9944 -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":3,"method":"system_health","params":[]}'
```

The genesis result and `chainId` must match the table. Check that peers connect
and the canonical height advances before enabling mining. Keep RPC bound to
loopback; remote spending tools should use an authenticated tunnel.

## Join from a source checkout

The commands above use `start.py` from a downloaded release archive. For a
source build, clone the release tag rather than an older commit or a moving
branch:

```bash
git clone --branch v0.11 --depth 1 https://github.com/Pauli-Group/Hegemon.git Hegemon-v0.11
cd Hegemon-v0.11
make setup
make node
```

If you already built this tag, reuse the compatible binary; no rebuild is
needed just to correct the launch arguments. Stop your previous node, choose a
new, unused data directory and start a syncing relay:

```bash
export HEGEMON_NODE_PATH="$HOME/.hegemon-node-v0.11-public"
export HEGEMON_SEEDS="hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333"
HEGEMON_MINE=0 HEGEMON_MINER_ADDRESS= ./start.sh
```

If that directory already contains another chain, keep it and choose a different
name. `./start.sh` selects the pre-mainnet profile and frozen manifest. Keep the
same `HEGEMON_NODE_PATH` when restarting; run the identity RPC checks above and
wait for the public chain to sync before mining. From this source checkout,
restart with `HEGEMON_MINE=1 HEGEMON_MINER_ADDRESS='<your-full-V8-public-address>' ./start.sh`
after creating and backing up your wallet. The `python3 start.py` examples in
this guide apply to extracted release packages, not the source checkout.

## Create and back up your wallet

Use the packaged `bin/private-spend` on a trusted local computer. The offline
bootstrap prompts for the encryption passphrase without echo and prints the
public full V8 address. Create a wallet outside the package and repository:

```bash
umask 077
mkdir -p "$HOME/.hegemon-wallets"
./bin/private-spend --wallet "$HOME/.hegemon-wallets/v011.wallet" bootstrap-new
./bin/private-spend --wallet "$HOME/.hegemon-wallets/v011.wallet" bootstrap-address
```

On Windows use `.\bin\private-spend.exe` and a private wallet path outside the
extracted package. Keep the complete address; a legacy GUI address is not a
v0.11 mining recipient. Back up the entire encrypted wallet file to separate
storage and keep the passphrase separately. The passphrase alone cannot restore
the random wallet root. Rehearse recovery to a new, nonexistent path:

```bash
./bin/private-spend --wallet '<new-restore-wallet>' \
  bootstrap-recover --source '<encrypted-wallet-backup>'
./bin/private-spend --wallet '<new-restore-wallet>' bootstrap-address
```

Compare the complete recovered address with the original. Recovery preserves the
source and requires a network rescan before spending. Keep spending keys, wallet
files and backups off mining servers and out of Git. A miner needs only the full
public payout address. Treasury operators keep using the already backed-up
approved treasury wallet; public miners should create their own wallet.

## Enable mining deliberately

After the relay is on the correct chain, stop it with Ctrl+C and restart with
your own full V8 public reward address. Linux or macOS:

```bash
HEGEMON_MINE=1 HEGEMON_MINER_ADDRESS='<your-full-V8-public-address>' python3 start.py
```

Windows PowerShell:

```powershell
$env:HEGEMON_MINE = "1"
$env:HEGEMON_MINER_ADDRESS = "<your-full-V8-public-address>"
py -3 start.py
```

The launcher requires `HEGEMON_MINE` to be exactly `0` or `1` and an address for
mining. It does not generate or copy a spending key to the server. All miners
must keep the approved seed list and synchronized clocks.

## Sync and spend with the native CLI

For funded wallet operations, stop your local relay and restart the package
with the explicit wallet-RPC option:

```bash
HEGEMON_MINE=0 HEGEMON_MINER_ADDRESS= python3 start.py --wallet-rpc
```

On Windows PowerShell:

```powershell
$env:HEGEMON_MINE = "0"
$env:HEGEMON_MINER_ADDRESS = ""
py -3 start.py --wallet-rpc
```

These commands clear any inherited mining recipient. The option enables the
node's unsafe RPC
methods, including transaction submission, **on loopback only** for your trusted
local CLI. The default safe RPC does not permit submission. Keep public mining
servers in the default safe-RPC mode; never expose wallet RPC to the internet.

`private-spend` verifies the manifest and expected genesis against that node,
synchronizes the encrypted wallet, and requires the current source-owned
spending authority. Use this same manifest/genesis for every network command.
The examples use Unix shell continuations; in PowerShell use
`.\bin\private-spend.exe` and put each command on one line:


```bash
./bin/private-spend --wallet '<encrypted-wallet>' \
  --manifest config/testnet/0.11/network-manifest.json \
  --genesis d9a8cfc158790b0251c7493d7261da771f7d57be63bce750ba8c1af5d92a9ad3 \
  --rpc http://127.0.0.1:9944 sync
./bin/private-spend --wallet '<encrypted-wallet>' \
  --manifest config/testnet/0.11/network-manifest.json \
  --genesis d9a8cfc158790b0251c7493d7261da771f7d57be63bce750ba8c1af5d92a9ad3 \
  --rpc http://127.0.0.1:9944 notes
./bin/private-spend --wallet '<encrypted-wallet>' \
  --manifest config/testnet/0.11/network-manifest.json \
  --genesis d9a8cfc158790b0251c7493d7261da771f7d57be63bce750ba8c1af5d92a9ad3 \
  --rpc http://127.0.0.1:9944 ordinary \
  --inputs '<spendable-note-position>' --recipient '<full-V8-recipient-address>' \
  --amount '<integer-HGN-atoms>' --fee '<integer-HGN-atoms>'
./bin/private-spend --wallet '<encrypted-wallet>' \
  --manifest config/testnet/0.11/network-manifest.json \
  --genesis d9a8cfc158790b0251c7493d7261da771f7d57be63bce750ba8c1af5d92a9ad3 \
  --rpc http://127.0.0.1:9944 submit '<retained-attempt-id>'
```

One HGN is 100,000,000 atoms. `ordinary` prepares and retains an exact attempt;
review its amount, recipient and fee, then submit that retained identifier.
Reward notes must first reach their 120-block maturity. Orphaned rewards and
transactions must be reconciled with the canonical chain.

The native CLI is the funded-send path qualified for this release. Desktop app
coverage establishes fresh-wallet synchronization, not funded GUI sends,
consolidation or private multisig. The live cutover exercised a 0.01 HGN payment
from a mature mining reward to the existing treasury, its 0.00001 HGN fee and
3.98999 HGN change, with canonical inclusion on OVH, dev and a local syncing node.
Unchanged HTLC and exact 120-block boundary qualification retain their original
lifecycle evidence. See the [release notes](https://github.com/Pauli-Group/Hegemon/blob/v0.11/docs/releases/v0.11.md).
