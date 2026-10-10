HEGEMON 0.10.1 — EXISTING PUBLIC TESTNET

This maintenance release follows the b819911dbf testnet consensus and includes
its sync pagination and mining-gate fixes. It joins the existing 0.10 testnet;
it does not migrate to the newer Bitcoin80 consensus or reset the chain.

Verified testnet genesis (full 32-byte hash):
0x506fc2cd5ed367cc68d6d23a987fe6e4a7916fde02a249105ab91884a1e6fa59

START A RELAY FIRST

Download the matching platform bundle, verify its published SHA-256 checksum,
and extract it into one folder. Keep the node binary and launchers together.
No installer, administrator account, wallet passphrase, or private key is needed.
Do not double-click the bare node executable: its default seed list is empty.

Windows x86_64:
  Double-click testnet-start.cmd, or run it from PowerShell:
    .\testnet-start.cmd
  This starts a separate PowerShell process with a per-process execution-policy
  override; it does not change the system's execution policy.

Linux x86_64 / macOS Intel / macOS Apple Silicon:
  Open a terminal in the extracted folder. Make the matching binary executable:
    chmod +x hegemon-node-linux-x86_64      # Linux
    chmod +x hegemon-node-macos-x86_64      # Intel Mac
    chmod +x hegemon-node-macos-arm64       # Apple Silicon Mac
  Run only the command appropriate to your platform, then:
    bash ./testnet-start.sh

The launcher explicitly sets:
  HEGEMON_SEEDS=hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333
  HEGEMON_MINE=0 (relay mode unless you explicitly select mining)
  HEGEMON_BOOTSTRAP_AUTHORING=0
  --dev --rpc-methods safe

In this release, --dev is the documented public-testnet launch profile when
paired with those seeds. The full genesis hash above is the chain identity.
RPC stays at http://127.0.0.1:9944; P2P uses port 30333.
At release preparation, the devnet seed was unavailable. Connection-refused
warnings for that seed are expected while it is down; check successful peers
and chain progress through the OVH seed. A seed connection alone does not prove
that your node has joined the canonical chain.

STATE AND PORTS

New launcher state lives persistently in:
  Linux / macOS: ~/.hegemon-testnet
  Windows:      %USERPROFILE%\.hegemon-testnet

Existing custom node and wallet directories are not discovered, copied, moved,
or erased. To resume an existing compatible 0.10 node directory, choose it
explicitly; do not run two nodes against the same directory:
  bash ./testnet-start.sh --data-dir "/your/existing/node-directory"
  .\testnet-start.cmd -DataDir "C:\your\existing\node-directory"

Use --rpc-port / --port on Unix, or -RpcPort / -Port on Windows, if another
local node already uses the default ports. Select distinct persistent data
for distinct node processes. Stop this node with Ctrl+C; restart with the same
data directory to resume. The launcher never deletes state or installs a service.

CHECK THE RUNNING NODE BEFORE MINING

In a second terminal, from the extracted folder:
  bash ./testnet-start.sh --status
  .\testnet-start.cmd -Status

This reads loopback RPC without opening another node. Responses identify:
  id 1: system_health — peers and isSyncing
  id 2: chain_getHeader — local tip; its number is hexadecimal
  id 3: chain_getBlockHash(0) — full genesis; must match the hash above
  id 4: hegemon_miningStatus — block_height, syncing, mining_sync_gate_open
  id 5: system_version — verify the running node is the 0.10.1 release

A queued broadcast, wallet balance, or locally found block does not prove
canonical synchronization. Wait for connected peers and completed catch-up.
Compare a block hash at the SAME HEIGHT with a trusted synced testnet operator.
Choose a height at or below both tips (1000 below is an example, not a checkpoint).

Unix (replace 1000 with the agreed height):
  curl --fail --silent --show-error -H 'Content-Type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"chain_getBlockHash","params":[1000]}' \
    http://127.0.0.1:9944/

PowerShell (replace 1000 with the agreed height):
  $body = '{"jsonrpc":"2.0","id":1,"method":"chain_getBlockHash","params":[1000]}'
  Invoke-RestMethod -Uri http://127.0.0.1:9944/ -Method Post -ContentType application/json -Body $body

A matching genesis plus matching canonical hash at the agreed height provides
chain comparison evidence; it does not prove that all later blocks are synced.
If height stalls or hashes differ, keep mining off and retain the binary version,
startup seeds/data path, RPC results, and import errors for debugging. Do not
blindly pull main, switch profiles, enable bootstrap authoring, or wipe data.

OPTIONAL MINING

After verifying canonical catch-up and enabling system time synchronization
(NTP/chrony on Linux, automatic network time on macOS or Windows), stop the relay
with Ctrl+C. Configure your existing PUBLIC shielded receive address, then restart:

Unix:
  export HEGEMON_MINER_ADDRESS="YOUR_EXISTING_PUBLIC_RECEIVE_ADDRESS"
  bash ./testnet-start.sh --mine

PowerShell:
  $env:HEGEMON_MINER_ADDRESS = 'YOUR_EXISTING_PUBLIC_RECEIVE_ADDRESS'
  .\testnet-start.cmd -Mine

The launcher requires a nonempty payout address for mining and preserves your
configured HEGEMON_MINER_ADDRESS and HEGEMON_MINE_THREADS. It does not open,
create, modify, or ask to export a wallet. A normal launch returns to relay mode,
even if HEGEMON_MINE was inherited from an earlier terminal session. The node's
sync gate controls when opted-in mining can begin; inspect status and canonical
hashes instead of assuming that a growing balance establishes readiness.

Wallet tools in this bundle connect to the local HTTP endpoint above. Use the
same wallet store you already own and synchronize it successfully before
interpreting its balance; a failed wallet scan can leave cached height/balance.

SYNC AN EXISTING WALLET

Keep the relay node running. In another terminal, use the wallet executable
for your platform and your EXISTING wallet store path. It prompts privately
for the passphrase; do not put the passphrase or keys into shell commands.
Replace the example path with your actual store:

Linux:
  ./wallet-linux-x86_64 node-sync --store "$HOME/.hegemon-wallet" --ws-url http://127.0.0.1:9944
  ./wallet-linux-x86_64 status --store "$HOME/.hegemon-wallet" --ws-url http://127.0.0.1:9944

macOS Intel: use ./wallet-macos-x86_64 with those same arguments.
macOS Apple Silicon: use ./wallet-macos-arm64 with those same arguments.

Windows PowerShell:
  .\wallet-windows-x86_64.exe node-sync --store "$env:USERPROFILE\.hegemon-wallet" --ws-url http://127.0.0.1:9944
  .\wallet-windows-x86_64.exe status --store "$env:USERPROFILE\.hegemon-wallet" --ws-url http://127.0.0.1:9944

The option is named --ws-url for compatibility; use the HTTP URL shown above.
If you chose another RPC port, use that port in both commands. Connection
refused means this endpoint is not listening in the same host/container;
confirm the node with the launcher status command before retrying the wallet.
Do not initialize a replacement wallet, reset its scan, or use --force-rescan
as a routine fix. A failed sync does not establish a zero on-chain balance.
