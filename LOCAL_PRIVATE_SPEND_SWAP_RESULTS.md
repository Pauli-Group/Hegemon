# Current private-spend / Bitcoin local swap results

All four scenarios passed using fresh isolated Hegemon Development and Bitcoin Core 32.1 regtest data. Branch: local-private-spend-htlc. Circuit, shared prover, wallet, node, protocol and Cargo source match main at 74910ff86514c2cbd93d7a7039e6b90b6e4600b6. No htlc-wip prover changes were carried over.

| Scenario | Result |
|---|---|
| Successful swap | Confirmed Bitcoin claim and canonical Hegemon claim; Bob received locked HGN |
| Bitcoin never funded | Canonical Hegemon refund returned Alice's locked HGN |
| Both refund | Confirmed Bitcoin refund and canonical Hegemon refund |
| Late claim | Confirmed Bitcoin claim, canonical Hegemon refund, then wallet rejected Bob's claim because the note was already spent |

The early-refund negative checks reached the private-spend relation and were rejected. Successful Hegemon actions were exported, submitted, compared byte-for-byte with canonical block actions, and reconciled with wallet mined status. Happy-case lock and claim actions contain SMZL proof bytes. Nodes had zero peers and all owned processes were stopped.

## Measurements

Linux wait4 measured each wallet child's high-water RSS. Wall time includes wallet unlock, synchronization and proof generation. Two prover workers were selected.

| Scenario | Operation | Seconds | Peak RSS GiB |
|---|---|---:|---:|
| happy | fund-bob | 93.407 | 1.654 |
| happy | lock | 62.152 | 1.655 |
| happy | claim | 62.120 | 1.656 |
| no_btc | fund-bob | 72.402 | 1.727 |
| no_btc | lock | 78.744 | 1.781 |
| no_btc | refund | 62.840 | 1.655 |
| both_refund | fund-bob | 92.291 | 1.655 |
| both_refund | lock | 89.467 | 1.655 |
| both_refund | refund | 179.049 | 1.936 |
| late_claim | fund-bob | 156.639 | 1.655 |
| late_claim | lock | 111.333 | 1.719 |
| late_claim | refund | 96.790 | 1.657 |

The first lock, claim and missing-Bitcoin refund ran separately and took about 62–63 seconds with about 1.65–1.66 GiB peak RSS. Later runs shared CPU or encountered different host load; their elapsed times are not controlled regression benchmarks. Peak proof-process RSS across the scenarios stayed below 2 GiB. These figures exclude the separately running node and total machine memory.

## Execution adjustments

An initial wallet build correctly rejected Development mode because its required feature was absent; rebuilding both binaries with wallet/private-spend-dev-artifacts fixed the invocation. The initial eight-block HTLC timeout was rejected by the current fourteen-block minimum; the harness now uses sixteen. A five-minute mining limit stopped the dual-refund case at H140 after Bitcoin's refund. That same fresh chain was restarted and its refund completed; Bitcoin's confirmed refund and zero peers were independently rechecked after restart. This is recorded as a resumed run, not an uninterrupted pass. The runner now allows fifteen minutes for each mining target and starts with H121 maturity to avoid an unnecessary later retarget boundary.

## Reproduce

From the repository root, build:

    RUSTUP_TOOLCHAIN=1.91.1 cargo build --locked --release -p hegemon-node --bin hegemon-node --features development-candidate,wallet/private-spend-dev-artifacts -p wallet --bin private-spend

Then run with an output directory that does not already exist:

    python3 scripts/local_private_spend_swap.py --output /absolute/new/output --bitcoind /workspace/bitcoin-32.1/bin/bitcoind

The private output directories contain disposable encrypted wallets, passphrase files and diagnostics. Public receipts with source/binary identities and complete measurements are in .agent/LOCAL_PRIVATE_SPEND_SWAP_RESULTS.json. These local manually advanced deadlines do not establish public-chain timeout margins, confirmation policy, cryptographic soundness or production authorization.
