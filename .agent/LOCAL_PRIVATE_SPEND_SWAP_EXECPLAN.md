# Local private-spend Bitcoin swap

## Purpose

Run real lock, claim and refund proofs using the current compact private-spend relation and fresh isolated Hegemon Development and Bitcoin regtest chains. Keep circuit and shared prover source identical to main. This plan follows .agent/PLANS.md.

## Progress

- [x] Created local-private-spend-htlc from origin/main.
- [x] Implemented scripts/local_private_spend_swap.py using private-spend CLI and existing Bitcoin helpers.
- [x] Build clean-source node with development-candidate and private-spend wallet (wallet/private-spend-dev-artifacts enabled).
- [x] Execute all four scenarios; retain public receipts in .agent/LOCAL_PRIVATE_SPEND_SWAP_RESULTS.json and report in LOCAL_PRIVATE_SPEND_SWAP_RESULTS.md.

## Context and implementation

The old launch_wallet_prepare example uses the standalone HTLC relation. The current wallet binary is private-spend. Bootstrap disposable encrypted wallets, print the compiled private-spend-only Development manifest, and keep its source identity. Use easy local PoW, empty HEGEMON_SEEDS, loopback listeners and Bitcoin regtest with listen/connect/discovery disabled. Fund Bob's fee note, lock Alice's HGN for Bob with an encrypted refund handoff for Alice, and prepare/export/submit retained exact actions. Compare exported bytes to canonical block actions and verify wallet mined status. The Bitcoin leg uses Core-signed PSBTs and confirmed witness preimage extraction. Each scenario owns fresh wallets and databases; stop owned processes on exit. wallet children use wait4 for peak RSS and wall-time measurements.

## Commands and validation

From the repository root build with cargo build --locked --release -p hegemon-node --bin hegemon-node --features development-candidate,wallet/private-spend-dev-artifacts -p wallet --bin private-spend. Run python3 scripts/local_private_spend_swap.py --output /workspace/private-spend-swap-results with Bitcoin Core installed at /workspace/bitcoin-32.1/bin/bitcoind. A successful run writes summary.json and per-scenario receipts. Failure logs remain private in the output directory. Never reuse that directory; a retry must use a new output path. Outputs contain disposable wallet stores and are mode 0700/0600.

## Decisions and discoveries

Use current private-spend operations and preserve source identity. Do not carry over htlc-wip prover changes or remove old modules. The four scenarios exercise release-compatible circuit code on a Development chain, not a public network or release authorization.

The initial wallet build omitted private-spend-dev-artifacts and correctly rejected Development mode before any proof. Rebuild node and wallet together with that feature. This does not edit the circuit source.

## Outcomes

Happy scenario passed in /workspace/private-spend-swap-run3/happy/receipt.json. Lock and claim measured 62.152 and 62.120 seconds, peak RSS 1,735,308 and 1,736,932 KiB via wait4. Circuit, wallet, node and protocol source match main. The missing-Bitcoin refund also passed at 62.840 seconds and 1,734,932 KiB peak RSS. Both-chain refunds passed after resuming the same chain at H140 following the original five-minute mining timeout. The resumed proof measured 179.049 seconds and 2,029,640 KiB while sharing CPU with the final scenario. Bitcoin refund and zero peers were rechecked after restart. The final late-claim case passed: Alice claimed Bitcoin, refunded Hegemon after timeout, and Bob's wallet rejected the spent note. All owned node processes stopped. The first fresh-chain attempt correctly rejected an eight-block timeout; the current private-spend minimum is fourteen and the runner now uses sixteen.

Mining now allows fifteen minutes per bounded height target. Initial maturity mining stops at H121 so the fourteen-block minimum lock window (configured as sixteen) can finish before another avoidable retarget boundary. Local Bitcoin deadlines are manually advanced; public-chain timing margins are outside this test.
