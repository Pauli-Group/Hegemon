# Experimental Hegemon–Ethereum public-testnet rehearsal

This test uses disposable HGN on v0.11 pre-mainnet and disposable ETH on
Sepolia. It is not a production swap tool. It has synthetic coverage but has
not yet completed a funded public Hegemon swap. Fixed block and time margins
are rehearsal choices, not guarantees about chain speed, confirmation or
finality. The local Hegemon node, the public Hegemon explorer and the Sepolia
provider are trusted. Do not use mainnet funds or valuable assets.

The separate Development rehearsal starts its own isolated nodes and must not
be pointed at the public Hegemon node. This runner never starts a node or
enables mining. It uses the operator's existing Hegemon node at a loopback
address and signs locally with the copied disposable test wallets. It needs a
`private-spend` 0.11.2 executable built from this branch: the official v0.11.2
release executable does not include this branch's `verify-htlc` command. The
runner checks the version and command at initialization, records the binary's
SHA-256 and refuses a changed executable in later steps. This checksum does not
prove its origin; the operator must build from trusted, reviewed source. The
wallet file and passphrase files must be private, user-owned regular files.

Alice locks 100,000 HGN atoms (0.001 HGN) for Bob. Bob locks 0.0001 Sepolia ETH
for Alice. Alice's Ethereum claim reveals the preimage, and Bob's Hegemon claim
uses the preimage observed in that confirmed Ethereum transaction. Before Bob
funds Ethereum, Alice's encrypted refund handoff is imported and both wallets
verify the same Hegemon note and agreed terms. Both wallets need ordinary HGN
fee notes. Alice also needs Sepolia claim gas; Bob needs ETH for the escrow and
its gas. Other participants and assets are outside this particular test.

## Preparation

Operator notes for the node this runner reads (it never starts or configures one). A node that follows the public
chain must be started with the approved seed list, `HEGEMON_SEEDS="hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333"`,
unless the list has been deliberately rotated. Every node and miner on the same network must use the same seeds,
otherwise they can partition and fork. Keep NTP or chrony enabled on the host: blocks and PoW timestamps beyond the
future-skew bound are rejected, and a drifting clock also makes the probe's 20-minute freshness check lie. Both apply
to any Hegemon leg of a swap, public or local. This runbook is the older, single-run path: new swaps go through the
swap engine (`scripts/SWAP_SCRIPTS.md`), and a public Hegemon adapter is the first item of the follow-up backlog in
`.agent/SWAP_SERIES_EXECPLAN.md`. Tool versions and the `pip --target` alternative to a virtual environment are in
`docs/SWAP_TOOLCHAIN.md`.

Work from a checkout containing this runbook and the current branch. Preserve
any unrelated local edits. Set `TEST_WALLETS` to the private directory with
`addresses.json`, `alice/`, `bob/`, and `hegemon-pre-mainnet/`. The transferred archive
normally contains those paths below a `testnet-wallets` directory. Use only
one copy of the test wallets at a time.

For example, after choosing the wallet directory in a private terminal, build
the branch's wallet in the separate checkout and create a Python environment:

```bash
cargo build --locked --release -p wallet --no-default-features --features rpc-client --bin private-spend
WALLET_BIN="$PWD/target/release/private-spend"
python3 -m venv "$HOME/.local/share/hegemon-swap-test-venv"
"$HOME/.local/share/hegemon-swap-test-venv/bin/python" -m pip install -r scripts/requirements-htlc-public.txt
SWAP_PYTHON="$HOME/.local/share/hegemon-swap-test-venv/bin/python"
"$SWAP_PYTHON" scripts/probe_hegemon_testnet.py --rpc http://127.0.0.1:9944 --check-public-tip
```

The probe must report `public_testnet_ready: true`. The wallet control RPC
must remain bound to loopback, and the existing node must have wallet methods
enabled. The public tip and common block timestamps must also be less than 20
minutes old. This clock-dependent threshold can reject a slow but healthy chain;
a matching explorer snapshot does not independently validate the chain. Check
both HGN and Sepolia balances before proceeding. Do not print or
paste wallet passphrases, private keys, or unrevealed preimages.

## Run one step at a time

Initialize once, then repeat `advance` only after reviewing the returned phase.
Each invocation completes at most one public submission. A `pending` response
means wait for confirmations and run `advance` again. The Hegemon lock and
claim steps can take substantial CPU time and memory; recorded child peak RSS
is the Linux process high-water mark, not a system-wide memory measurement.

```bash
"$SWAP_PYTHON" scripts/public_hegemon_eth_rehearsal.py init --directory "$TEST_WALLETS" --wallet-binary "$WALLET_BIN"
"$SWAP_PYTHON" scripts/public_hegemon_eth_rehearsal.py advance --directory "$TEST_WALLETS" --wallet-binary "$WALLET_BIN"
"$SWAP_PYTHON" scripts/public_hegemon_eth_rehearsal.py status --directory "$TEST_WALLETS" --wallet-binary "$WALLET_BIN"
```

`complete` means the runner observed both claims with its configured
confirmation thresholds and Bob's wallet reported a new ordinary note of the
expected value. The payout-output association relies on the trusted wallet's
construction and no concurrent wallet activity; it is not independently bound
to the exact claim output. Save public transaction IDs, block hashes and proof
metrics separately from private wallet records. The secret may be disclosed to the Sepolia provider
during gas estimation before a claim is broadcast; it cannot be made private
again after that point.

## Interrupted actions and refunds

If the phase ends in `_inflight`, stop. A proof may already be reserved or a
transaction may already have been broadcast even when a command reported an
error. Inspect the local wallet's `status`/`attempts`, the private journal, and
the relevant chains before deciding how to recover; do not blindly rerun the
action. The runner deliberately refuses to advance an uncertain phase.

The private `hegemon-eth` directory contains a raw 32-byte `secret`, encrypted
`refund.bin`, its separate `refund.pass` file, Hegemon action exports and
transaction journals. They are mode 0600 inside a mode 0700 directory, but the
handoff passphrase is stored alongside the handoff for this disposable test.
Protect the directory and keep it outside Git and chat. Hegemon action exports
may include a disclosed preimage. Do not delete the refund handoff or wallet
files while funds are locked.

If the Hegemon lock was confirmed but refund import did not complete, inspect
the exact lock action and block first, then use the wallet's
`import-refund-handoff` with `refund.bin`, the canonical lock block height,
refund address index 0 and the local handoff passphrase. After the Hegemon
timeout, Alice can use the wallet's `refund` command with the imported HTLC
position, a separate ordinary Alice fee-note position, Alice's Hegemon address
and a fee. Record the returned attempt before submitting it once and confirm
the resulting action. The rehearsal does not automate this refund.

If the Ethereum lock remains unclaimed after its expiry, Bob can recover it
using the escrow's `refund()` method from Bob's Sepolia wallet. First verify the
exact contract, chain, expiry and unspent state, and inspect any uncertain
claim or submission. Journal the signed refund before submitting once. The
runner does not automate that recovery. If a preimage has already been sent to
an Ethereum provider, assume it is disclosed even if no claim is confirmed.
