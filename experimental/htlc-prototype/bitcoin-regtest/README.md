# Bitcoin Core regtest HTLC harness

This harness runs a real Bitcoin Core daemon, funds two P2WSH locks, confirms a
hashlock claim, and refunds the other lock at its absolute height deadline.
Bitcoin Core evaluates every witness. The Python code only constructs and signs
transactions using BIP143 and secp256k1.

It is a Bitcoin-only component test. A passed receipt is **not a completed
HGN/BTC swap**, a Hegemon proof, or production/release authority. A wallet fixture
adds an exact script/offer binding, but its Hegemon offer is still not funded.

The retained [component receipt](receipts/core-31.1-bitcoin-component.json) passes
against verified Core 31.1 at final height 122, in 2.730 seconds with 59,400 KiB
peak daemon resident memory. It binds the harness and binary SHA-256 values and
explicitly records `wallet_fixture_checked: false`. The integrated wallet fixture
and real Hegemon leg are subsequent gates.

The subsequent [wallet-bound receipt](receipts/core-31.1-wallet-bound.json) passes
the same cases against the actual wallet export, with
`wallet_fixture_checked: true`, in 3.080 seconds with 59,024 KiB peak daemon RSS.
It binds fixture SHA-256
`20bedf0e1b7eb4b0291a7ce682452f3ecd45b74e8c23100f4c78e55537f17114`.
The Hegemon leg remains unexecuted in this harness and the full atomic-swap gate
remains open.

## Run

Use Linux x86_64, Python 3 with `cryptography`, `curl`, GPG, and a fresh scratch
directory outside Git. The verified binary is installed only in scratch; no
system service or system package is installed. The pinned release is Bitcoin
Core 31.1 from the [official release directory](https://bitcoincore.org/bin/bitcoin-core-31.1/),
following the project's [signature-verification instructions](https://bitcoincore.org/en/download/).

From the repository root, choose a task-local parent and an available CPU core:

```sh
mkdir -m 700 -p /tmp/premainnet-bitcoin
bash experimental/htlc-prototype/bitcoin-regtest/fetch_core.sh /tmp/premainnet-bitcoin/vendor
python3 experimental/htlc-prototype/bitcoin-regtest/run_regtest.py prepare \
  --work-dir /tmp/premainnet-bitcoin/run-001
```

The prepare command creates `private.json` (private scalars and unrevealed
preimage, mode 0600) and `public-terms.json` (hashlock, public keys, amount,
deadline, and confirmation depth). Keep all keys and chain data outside Git.
Only the latter file may be passed to the Hegemon wallet fixture exporter:

```sh
cargo run -p wallet --example htlc_public_fixture -- \
  /tmp/premainnet-bitcoin/run-001/public-terms.json \
  > /tmp/premainnet-bitcoin/run-001/wallet-fixture.json
```

The fixture exporter lives in the companion wallet change and requires that
change to be integrated. The harness checks its `offer.hashlock`, `offer.bitcoin`,
`witness_script_hex`, and `script_pubkey_hex` against the exact script sent to
Core. Without `--wallet-fixture`, a run explicitly records no wallet binding.

On the authorized Linux host, `/home/ubuntu/hegemon-premainnet/bitcoin-regtest`
was the scratch parent and core 2 was reserved for this task. A typical bounded
run there is:

```sh
systemd-run --user --scope --property=MemoryMax=1G --property=CPUQuota=100% \
  --property=AllowedCPUs=2 \
  python3 experimental/htlc-prototype/bitcoin-regtest/run_regtest.py run \
  --work-dir /home/ubuntu/hegemon-premainnet/bitcoin-regtest/run-001 \
  --bitcoind /home/ubuntu/hegemon-premainnet/bitcoin-regtest/vendor/bitcoin-31.1/bin/bitcoind \
  --wallet-fixture /home/ubuntu/hegemon-premainnet/bitcoin-regtest/run-001/wallet-fixture.json \
  --release-receipt /home/ubuntu/hegemon-premainnet/bitcoin-regtest/vendor/release-verification.json \
  --receipt /home/ubuntu/hegemon-premainnet/bitcoin-regtest/run-001/receipt.json --cpu 2
```

The daemon also enforces a 1 GiB address-space limit and one-core affinity, one
RPC worker, a 32 MiB database cache, and a 16 MiB mempool. RPC binds only to
loopback with cookie authentication. Peer listening, DNS discovery, and network
activity are disabled. This chain uses valueless regtest coins and no peers.

## What a passed receipt checks

The expected lock amount and exact script must be unspent at the required
confirmation depth before any claim witness is constructed. Core rejects a
wrong secret, a 31-byte secret, a wrong claim key, an early refund, a wrong refund
key, and a second spend of the consumed claim output. A valid claim is confirmed,
and its exact 32-byte preimage is recovered from Core's decoded transaction
witness. A refund with locktime 120 is rejected at tip 119, accepted at tip 120,
and mined in a later block. This distinction follows Bitcoin's transaction
finality boundary, not a comparison to Hegemon height units.

The harness makes a clean durable checkpoint after confirming both locks, then
abruptly kills its daemon after broadcasting the claim. The persisted exact
transaction is recovered by txid or resubmitted byte-for-byte. This deliberately
tests uncertain claim submission against an already durable offline chain. It
does not kill the harness process or claim that newly mined, unflushed regtest blocks survive a process kill
without peers. A final clean restart checks the confirmed claim, refund, and
spent outputs again.

`recovered-secret.json` contains the now-public preimage recovered from the
confirmed claim and its source txid. It stays in scratch for a Hegemon integration
runner. `submitted-transactions.json` retains exact signed Bitcoin bytes locally.
Only sanitized `receipt.json`, public wallet fixtures, and release verification
receipts belong in the repository. A receipt marked `incomplete` is not a pass.

Each run refuses an existing chain directory or receipt. Failures retain their
keys, logs, and chain state for diagnosis and stop only the daemon created by the
harness. Retry in a new directory; do not delete retained runs to hide failures.

Core RPC references: [decodescript](https://bitcoincore.org/en/doc/31.0.0/rpc/rawtransactions/decodescript/)
and [testmempoolaccept](https://bitcoincore.org/en/doc/31.0.0/rpc/rawtransactions/testmempoolaccept/).
