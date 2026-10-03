# October 2 combined-source validation

This report covers the runtime source at `e471ada3c5adb8f9a88c99227008ddddb56ed096`, following the all-green wallet/profile and contiguous-memory publication `561095f691ffbdf7cf6438986dd1926f42ae947b`. Later mechanical policy evidence and this report do not alter the executable proof source. It is a PR validation report, not deployment or production activation.

## Integrated scope

The source combines the shared wallet profile route, contiguous prover tapes, bounded independent V8 proof verification with canonical ordered state application, isolated Linux process supervision, and the standalone HTLC hashlock experiment. No production proof geometry, carrier-size cap or activation policy changes. The HTLC experiment is not admitted by the production route.

The sync-prefetch candidate is intentionally separate at `153fa3236109747db9f4e0ea728053c9f93344ff`. Its focused tests pass, but a three-run comparison with injected 100ms response latency measured only a 4.69% median improvement, from 5.810186s to 5.537747542s over 192 blocks. That synthetic-only benefit does not yet justify adding its scheduling state to this release.

## Local checks

From the combined checkout, the following passed with Rust 1.91.1:

    CARGO_BUILD_JOBS=2 CARGO_NET_OFFLINE=true cargo test --locked --offline --profile retained-proof -p hegemon-node --features poseidon2-v8-retained-test-support --lib --no-run
    target/retained-proof/deps/hegemon_node-880248efd9e2b700 --test-threads=1
    CARGO_BUILD_JOBS=2 CARGO_NET_OFFLINE=true cargo clippy --locked --offline -p hegemon-node --all-targets --features poseidon2-v8-retained-test-support -- -D clippy::correctness -D clippy::suspicious -D unused_must_use -D unsafe_op_in_unsafe_fn
    cargo fmt --all -- --check
    python3 -I -B scripts/test_check_ci_release_gate_policy.py
    python3 -B -m unittest discover -s scripts/tests -p test_rp05_crosshost_supervisor.py

The full node suite passed 765 tests, zero failures, 18 explicit ignores, in 55.87s; peak RSS was 1,103,069,184 bytes. The proof-dependent ignored tests below were then run explicitly. The broker suite passed eight Darwin tests with one Linux-only skip; that same broker's Linux suite previously passed all nine. Existing style warnings were not relabeled as errors or removed. The pending-action encoding regression now uses a current ciphertext produced by the real wallet builder instead of an obsolete historical ciphertext, preserving strict payload decoding and the original encoding assertions.

The isolated HTLC parent passed 11 tests, strict Clippy and formatting. Its backend binding test, current-source honest proof, actual invalid-witness proof rejection and fresh-process public-artifact verification passed. After removing two trailing blank lines from the isolated manifests, its source binding was regenerated and checked again: 311,682 proof bytes, 7.939s proving with two worker threads, 0.149s verification, and 1,565,294,592-byte peak RSS. The earlier four-thread run measured 4.442s. Both exact source closures and receipts are preserved in `experimental/htlc-prototype/proof-backend/MEASUREMENTS.md`. Full HTLC policy proofs, production size/security qualification and enabled swaps are not claimed. These isolated-manifest changes are outside the RP05 qualification source inventory.

## Fresh proof and lifecycle evidence

Both artifact generators were built with `--locked --offline --profile retained-proof -p transaction-circuit --features rp05-dev-artifacts`, using the `rp05_smza_qualification_artifact` and `rp05_smza_disjoint_spends_artifact` examples. Each create-only generation was followed by a separate `verify DIRECTORY` process.

The qualification pair is retained at `.agent/artifacts/smallwood-poseidon2-v8-smza/rp05-qualification-lanes/overnight-combined-e471ada3/pair`. Manifest SHA-512:

`ae438d066fd7f2f4da91e054baaa961d12281f27f584c2a4bc49aa7e5579de2d83fff0a1dbbb1e516973f07c011991e03ab217490af80dfc6f5720844ce43469`.

Source-inventory root SHA-512 (1,358 files):

`98a47492b8616247470d5dd9973a0fa7128c62e2aa662d1a4755ba26f59df66e398c6026bedd0ec7d44f77a99109134e92d89ef02f0978ab221c7171b1523614`.

The two proofs are 163,601 and 163,729 bytes. Their inline carriers are 169,035 and 169,163 bytes. Generation/readback verifies the exact source, distinct proofs and transcript randomness, and unchanged carrier bytes. Production-authorized and production-eligible remain false. The external timing wrapper reported 89.64s but could not read a sandbox-restricted timing sysctl, so no peak-RSS claim is made for this pair; the independent verification command exited zero.

With `HEGEMON_TEST_RETAINED_SMZA_MANIFEST_PATH` pointing to that manifest and `HEGEMON_TEST_RETAINED_SMZ9_MANIFEST_SHA512` set to its SHA-512, the following exact ignored tests passed:

    native::poseidon2_v8_verifier::tests::retained_smza_pair_survives_native_pending_mining_reorg_restart_and_fresh_import
    native::poseidon2_v8_verifier::tests::retained_smza_actual_socket_process_carriers

The in-process reorg/restart/fresh-import test passed in 2.79s. The three actual-socket episodes passed in 76.01s, including a genuine newly generated wallet spend: 163,665 proof bytes, 169,099 inline bytes, 169,324 pending-action bytes, 43.285863333s proving. Source, relay, restarted and fresh node processes agree; wallet receive/spend/close-reopen assertions and malformed-input rejections pass. This is isolated local development-chain evidence, not public-network activation. Receipt `.agent/rp05-wallet-memory/combined-actual-socket-carrier-receipt.json` SHA-256:

`85eae1e70abe2ce6bb8ff0562ae5ca7617420be003584a9cc40554e0ec281951`.

The fresh disjoint-input pair is retained at `.agent/artifacts/smallwood-poseidon2-v8-smza/disjoint-combined-e471ada3`; manifest SHA-512:

`c9e45809bcb154d7e7ecb36cdb0a1fbf10e2a6f48064a56d5af9c46b3b2e1350a50810dfdf5eefbfad1559486158e2440956483ad0822f0f50092c707f3a4e1e`.

With `HEGEMON_TEST_DISJOINT_SMZA_DIRECTORY` set to that directory, `native::poseidon2_v8_verifier::tests::bounded_native_disjoint_smza_block_survives_restart_and_fresh_import` passed in 1.42s. This verifies actual same-parent independent spends, ordered block application, exact proof carriers, restart/fresh import, and duplicate-nullifier/later-mutated-proof rejection without durable state changes. The throughput benchmark remains a separate component measurement, not a network or end-to-end block TPS result.

## Isolated Linux/macOS lifecycle

Linux compiled the same executable source tree as `e471ada3` using Rust 1.91.1, the retained-proof profile, two build jobs and its isolated target directory. Build time was 6m56s and peak build RSS 2,745,720,832 bytes. The Linux harness SHA-512 is:

`79a6a2ab70e1bd9da7d7efaa6a89f6cc89e3fe603e13b1aaf6c90c1f05d9f7adac6e806b003448c6ff6cf9b833d52316bfffbdfbd1262a100f533d73b249ad7b`.

The exact 19-file public-fixture-only qualification pair was copied unchanged into the isolated source directory. It contains public statements, proofs, carriers, source metadata and committed development fixtures, not operator secrets, wallet databases or private witnesses. Its manifest SHA-512 and the 1,358-file source-inventory root match the local pair above. The initial transfer guard refusal was resolved by inspecting that exact payload and resubmitting it with the public-test-only evidence; no alternative transfer path was used.

The exact ignored selector `native::poseidon2_v8_verifier::tests::retained_smza_crosshost_actual_socket_process_carriers` passed 1/1 in 44.87s, exercising both fixed-fixture episodes with Linux source and macOS relay/restarted/fresh node processes through private SSH-forwarded loopback connections. Initial invocations stopped before node startup because of an absolute manifest path and sandbox-denied loopback binding; the required relative path and scoped network permission resolved those environment errors. The successful receipt explicitly records `wallet_proof_episode=null`: genuine wallet proving is covered by the separate local episode, not falsely attributed to Linux.

Both owned Linux test process groups and listeners were absent after completion. The existing `hegemon-dev` testnet service retained its original process and executable, zero restarts, unchanged genesis, two peers, synchronized time and synced chain state; no current-testnet service/configuration/data or public port changed. Detailed operator checks remain in the local cross-host report.

Receipt `.agent/rp05-wallet-memory/combined-crosshost-socket-carrier-receipt.json` SHA-256:

`bb58922638e7abf36335f90972ca7fd1aad94afa22b8d1dcff7756676da4a89a`.

## Policy and publication

Mechanical review-source fingerprints were refreshed for changed inputs; review statuses, external assumptions and production-authority flags are unchanged. The focused governance suite passed 14/14, and the active-goal and blueprint/claims checks passed after their evidence refresh. No Lean theorem was changed or newly claimed by this engineering patch.

The published wallet/memory head already has 24 passing CI checks. Final follow-up publication and its exact-head CI are tracked in the overnight checklist. Build and lifecycle evidence remain distinct; no merge, network deployment or mainnet activation is claimed.
