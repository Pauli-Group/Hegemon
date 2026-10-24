# Validate the Bitcoin half of an HGN/BTC swap on regtest

This living plan follows `.agent/PLANS.md`. Only this directory is owned by this task; Hegemon wallet and consensus work belongs to other workers.

## Purpose / Big Picture

Exercise the Bitcoin counterpart of a Hegemon-first atomic swap against Bitcoin Core's real script interpreter. Regtest is Bitcoin's isolated private test chain: its coins have no value and it needs no peers. A successful run must create a pay-to-witness-script-hash (P2WSH) output, spend it with a signed hashlock claim, refund another output after an absolute block-height deadline, and reject invalid attempts. This is Bitcoin-side evidence; completing an HGN/BTC swap additionally requires the real Hegemon lock and claim/refund proof paths and wallet-produced offer fixtures.

## Progress

- [x] Created isolated managed worktree from `70b062f` and inspected the existing HTLC prototype boundary.
- [x] Coordinated remote CPU core 2 with the development build owner; cores 0 and 1 remain untouched.
- [x] Located official Bitcoin Core 31.1 release, checksum, signature, and Core RPC documentation.
- [x] Verified archive SHA-256 and release signature; unpacked only task-local executable files.
- [x] Implemented the real-daemon harness and public fixture interface.
- [x] Executed positive, negative, confirmation, crash/restart, and preimage recovery cases against Core 31.1 in remote run-003.
- [x] Added source/binary fingerprints, execution timing, and measured child peak RSS to the final receipt format.
- [x] Validated final source in run-004 and retained its sanitized component receipt and release-verification receipt.
- [x] Consumed the actual wallet export in run-005 and retained a distinct `wallet_fixture_checked: true` receipt. The earlier independent component receipt remains unchanged.

## Surprises & Discoveries

The authorized Ubuntu development host has Python 3 and `cryptography` 3.4.8, but no Bitcoin Core. Bitcoin's ordinary wallet signer does not construct arbitrary HTLC witness stacks; the harness will serialize and sign the witness transaction using secp256k1 and have Bitcoin Core validate it. It will not implement a substitute script interpreter.

The first run hit the 1 GiB address-space ceiling because Core defaulted to sixteen RPC workers. The fix keeps the ceiling and uses one RPC worker plus two glibc allocation arenas. The second run reached a valid accepted claim and all initial negative checks, but abruptly killing the fresh isolated daemon before any flush lost its newly mined block index. Without peers, that chain cannot recover the blocks automatically. The crash scenario now establishes a clean durable confirmed-lock checkpoint, then targets uncertain claim submission. Run-003 passed and explicitly recorded that the claim was resubmitted from the exact stored bytes because the killed daemon did not retain its mempool. This proves that bounded scenario, not arbitrary power-loss durability or a restarted wallet process.

## Decision Log

Use official Bitcoin Core 31.1, currently listed by the project's download page. Download its x86_64 Linux archive, SHA256SUMS, SHA256SUMS.asc, and the release builder key linked by the official verification instructions. Keep an isolated GPG keychain and record exact verified fingerprints and archive hash.

Use one daemon pinned to remote core 2, a 1 GiB memory ceiling, a fresh restrictive-permission data directory, RPC bound to loopback, no listening peer socket, and disabled networking. No existing service or wallet is touched. Private keys are freshly generated and stored outside Git with restrictive permissions; published receipts contain public scripts, transaction IDs, hashes, and validation outcomes only.

The wallet exporter receives only `public-terms.json` and emits `offer`, `witness_script_hex`, `script_pubkey_hex`, and `offer_id_hex`. Its full Hegemon offer remains an unfunded public fixture. The Core harness requires its exact hashlock, Bitcoin terms, witness script, and output script to match before claiming wallet binding. No copied implementation or Python-generated substitute is labeled wallet execution.

## Outcomes & Retrospective

The final executable Bitcoin component passed run-004 with final height 122 in 2.730 seconds, with 59,400 KiB maximum child resident memory. Its claim txid is `393c44d2fe4e4618422d4857250a8f304f341761621e9a56c708ff6657dbbb05`, and its refund txid is `4e515f7d962b432f39e27ffea58e159a36942bc0821a91dbff8d0978ef876f80`. The refund was rejected at tip 119 and accepted at tip 120, then confirmed. `receipts/core-31.1-bitcoin-component.json` binds the final harness SHA-256 `ee83e933601e5affc8bde5f874e4c72245d07fbf3edd811a610e832599118562`, exact binary SHA-256, public scripts, transaction ids and Core rejection reasons. Wallet-bound execution remains a follow-up dependency because the wallet exporter needs its integrated Rust modules built. No Bitcoin-side result implies Hegemon production authority or completed cross-chain atomicity.

The follow-up wallet export was generated by the integrated wallet executable from the same public terms. Run-005 passed every component case with wallet binding enabled in 3.080 seconds, with 59,024 KiB maximum daemon RSS and final height 122. The exported fixture SHA-256 is `20bedf0e1b7eb4b0291a7ce682452f3ecd45b74e8c23100f4c78e55537f17114`, and its offer id is `1fb606fc69f16c4e290c6a527590479f8e4b9982768223f495bc93fb827aa367`. `receipts/core-31.1-wallet-bound.json` is the distinct retained result. Its confirmed claim txid is `d5a9a5a7f2a0e73c4abcb6076ee7fb966e6e6a30e541aa001d1df481a0b74a68`, and refund txid is `066a62af82b942a8984dfa5613f227846112cacbb5e01ef2dd778b0b0dde4628`. The daemon stopped after validation. Private keys remained on the host; only the public wallet fixture was transferred into this run. The Bitcoin wallet-binding milestone is complete; the Hegemon runtime leg and full atomic-swap qualification are outside this receipt.

## Context and Orientation

`experimental/htlc-prototype` contains a separate experimental hashlock relation. This directory adds only Bitcoin integration tooling. The Bitcoin script has a claim branch requiring a 32-byte SHA-256 preimage and the claimant's secp256k1 signature, and a refund branch requiring the refund key and `OP_CHECKLOCKTIMEVERIFY` with an absolute Bitcoin block height. The Hegemon deadline is longer in elapsed-time assumptions; raw Hegemon and Bitcoin heights must never be directly compared.

Local scratch is `/private/tmp/premainnet-bitcoin`; remote scratch is `/home/ubuntu/hegemon-premainnet/bitcoin-regtest` on SSH alias `hegemon-dev`. Vendor binaries, chain data, cookie credentials, and private keys stay there. Repository output is public source and sanitized JSON receipts only.

## Plan of Work

Milestone one is a verified task-local Bitcoin executable. `fetch_core.sh` downloads the pinned release archive, authenticates its checksum manifest against a pinned release-builder fingerprint, checks the archive SHA-256, and extracts only two command-line executables. The result is an executable file under scratch and a public provenance JSON file. No system installation is needed.

Milestone two is an independently passing Bitcoin lifecycle. `run_regtest.py prepare` generates ephemeral claim/refund keys and exact public terms. `run_regtest.py run` starts Bitcoin Core, funds two lock outputs, tests invalid witnesses, confirms a claim, recovers its published preimage, verifies double-spend rejection, restarts the daemon, and performs a mature refund. The reader can observe `status: passed` in the receipt and the exact reject reasons for each negative case. This milestone is complete in run-003.

Milestone three binds the wallet's actual output. After the companion wallet change is integrated, run its `htlc_public_fixture` example against the prepared public terms. Supply the resulting JSON as `--wallet-fixture` in a fresh Core run. The acceptance observation is `wallet_fixture_checked: true` in a passed receipt. This milestone completed in run-005. `README.md` contains the complete commands and explicit evidence boundaries.

## Concrete Steps

From the repository root, prepare a new run with:

    python3 experimental/htlc-prototype/bitcoin-regtest/run_regtest.py prepare --work-dir /tmp/premainnet-bitcoin/run-new

Only public-terms.json may be exported to the wallet fixture executable:

    cargo run -p wallet --example htlc_public_fixture -- /tmp/premainnet-bitcoin/run-new/public-terms.json > /tmp/premainnet-bitcoin/run-new/wallet-fixture.json

Run the harness with explicit `--bitcoind`, `--work-dir`, `--receipt`, `--wallet-fixture`, and `--cpu` paths as shown in README. On the authorized Linux host it is wrapped by `systemd-run --user --scope --property=MemoryMax=1G --property=CPUQuota=100% --property=AllowedCPUs=2`. The work directory must be outside every Git checkout and must not contain an existing chain. Receipts are exclusive-created, never overwritten. The harness always stops its own daemon on exit.

The actual run-003 command used `/home/ubuntu/hegemon-premainnet/bitcoin-regtest/run-003`, the verified vendor `bitcoin-31.1/bin/bitcoind`, CPU core 2, and `receipt.json`. It returned:

    {"status": "passed", "wallet_fixture_checked": false}

The wallet-bound follow-up used the same verified binary, script source, limits, and public terms, but a new `run-005` directory. Its exact remote command was:

    systemd-run --user --scope --property=MemoryMax=1G --property=CPUQuota=100% --property=AllowedCPUs=2 python3 /home/ubuntu/hegemon-premainnet/bitcoin-regtest/code/run_regtest.py run --work-dir /home/ubuntu/hegemon-premainnet/bitcoin-regtest/run-005 --bitcoind /home/ubuntu/hegemon-premainnet/bitcoin-regtest/vendor/bitcoin-31.1/bin/bitcoind --receipt /home/ubuntu/hegemon-premainnet/bitcoin-regtest/run-005/receipt.json --release-receipt /home/ubuntu/hegemon-premainnet/bitcoin-regtest/vendor/release-verification.json --wallet-fixture /home/ubuntu/hegemon-premainnet/bitcoin-regtest/run-005/wallet-fixture.json --cpu 2

It returned `status: passed` and `wallet_fixture_checked: true`.

## Validation and Acceptance

Acceptance requires actual Core mempool and block results, including a confirmed lock, accepted and confirmed claim, wrong-secret rejection, wrong-key rejection, early-refund rejection, mature-refund acceptance, spent-output rejection, transaction-ID and preimage recovery from Core, and persistence across abrupt daemon restart. Store the Core version, archive hash, script, height boundaries, transaction IDs, and exact reject reasons in the receipt. Final cross-chain acceptance remains pending until the wallet fixture and Hegemon integration are exercised together.

## Idempotence and Recovery

Every run uses a unique directory and refuses collisions. Failed runs retain local logs and keys for diagnosis and stop only the process they launched. Retrying creates a new run; it does not delete old chain data. Downloads may be reused only after checksum verification.

## Artifacts and Notes

Official sources: https://bitcoincore.org/en/download/ ; https://bitcoincore.org/bin/bitcoin-core-31.1/ ; https://bitcoincore.org/en/doc/31.0.0/rpc/rawtransactions/decodescript/ ; https://bitcoincore.org/en/doc/31.0.0/rpc/rawtransactions/testmempoolaccept/ .

## Interfaces and Dependencies

Python 3, Python `cryptography`, and official Bitcoin Core `bitcoind` are required. No Rust workspace build is needed for the independent Bitcoin harness. The wallet worker owns the exact offer schema and supplies public hashlock, compressed claim/refund public keys, Bitcoin refund height, and witness-script bytes. Public fixture transport must not contain a WIF or a private scalar.

Archive SHA-256 is `b80d9c3e04da78fb6f0569685673418cf686fadba9042d926d13fb87ff503f9e`. GPG verified signing subkey `CFB16E21C950F67FA95E558F2EEB9F5CC09526C1` under pinned primary key `E777299FC265DD04793070EB944D35F9AC3DB76A`. The successful checksum output was `bitcoin-31.1-x86_64-linux-gnu.tar.gz: OK`. The public verification receipt is under this directory's `receipts` subdirectory.
