# Fresh proofs for the repaired SMZ9 relation

On 2026-09-07, two fresh maximum-shape proofs were generated, retained and
cross-verified at source revision
`4a0acb9be94ff15441855cbb9ea7051ca104998a`. The primary and independent runs
use the repaired 853,429-byte program with SHA-512
`180fca50376f7573cacedfb5465a0b4d6bf5c61637152035a682d21038016d2239e2f8b50605f36baa635038348dc984197d6df29347e17e1150c24ff737de84`.
The emitted program was compared byte for byte with
`testdata/formal_core_vectors/poseidon2_v8_relation_program.bin` before proving.

The retained root is
`.agent/artifacts/smallwood-poseidon2-v8/hgv8rp03-b1e5c143f7abf052`.
Its exact 29 read-only payload files total 8,419,305 bytes. All earlier retained
directories and the historical fixed manifest were preserved. The fixed
manifest still has SHA-512
`6f07e9751f9af6da1710f73b9e1fc689db2a160b357644cf1ba076bcd0b70da5455a4dd30bee8ea71ee64b9df5d2ecbe2f51351a055deb32a4161516d9adbfe3`.

## Measurements

| Measurement | Primary | Independent |
| --- | ---: | ---: |
| Inner proof bytes | 122,735 | 122,735 |
| Native leaf bytes | 128,133 | 128,133 |
| RPC envelope bytes | 128,165 | 128,165 |
| SCALE inline arguments bytes | 128,169 | 128,169 |
| Complete PendingAction bytes | 128,394 | 128,394 |
| Proving plus internal verification | 44.696 s | 46.318 s |
| Immediate independent source-factory verification | 56 ms | 53 ms |

Both complete actions have 2,903 bytes of headroom under the 131,297-byte cap.
The source projection remains 122,863 proof bytes and 128,522 complete action
bytes. Both fixtures spend the same two positive action-11 coinbase notes at
positions zero and one, with parent height two and two active inputs and outputs.
The repaired geometry has 686 witness rows, 43,904 packed witness words,
19,935 linear constraints and 830 nonlinear constraints.

Primary bundle:
`retained_proof_primary/smz9-fe2cfc6917b54fda12c24fc8`.
Its proof SHA-512 is
`fe2cfc6917b54fda12c24fc8cadb77486297b4fb168b8031c87ba449a9296a3ff58c1596ba5fe620ce225cdff2a97dd96d16bc493e1193f3441e43e8dca34b3c`;
its complete action SHA-512 is
`55a36a49cabf63f4d3db59f113903a5234d0beaa73747dc3cc8a2f5e713c7faa0e7ff5da1e96fae235e162fe5c136d81e6b9e63e8cf5d71493b01795f2a2a77b`.

Independent bundle:
`retained_proof_independent/smz9-fe942e23e9ac2d0ec2a07440`.
Its proof SHA-512 is
`fe942e23e9ac2d0ec2a07440da6afa05df6f9b25c804e7d6cd5f4cb4c5bbde51c1ada9df9032c9358f2d5a7fade5db919dc5a896f2a6fe718015f67c367d2607`;
its complete action SHA-512 is
`f82ddfa041471537e4b8637acafb1130da4be65ff03167b604913e6d7311d88dabaa4d1c3af17ac8ab7e6098623188fcbc80ae940d3c279d8546cfebe2ddebf8`.

## Build and verification evidence

Build A used the existing target directory with
`cargo build --locked --offline --profile retained-proof -j 1 -p transaction-circuit --example smallwood_poseidon2_v8_artifact`
and completed in 74 seconds. Build B ran the same command with a fresh
`CARGO_TARGET_DIR=/private/tmp/hgv8rp03-repaired-proof-4a0acb9b.MM0MEA/build-b`
and rebuilt all dependencies in 161 seconds. The resulting binaries compare
byte for byte. Both are retained under `generator-binaries/build-a` and
`generator-binaries/build-b`; each is 2,433,632 bytes with SHA-512
`53dbeaca52bb20e962972027cbd12afe347bd1637ed39130166b5005c916a4e7da2fe4a7d7420c67f4fe951356a02ea29ec6249c523dea475ff60e04244cc579`.

The release source inventory was frozen throughout both builds, both proof
runs and all cross-verifications. It contains 972 files totaling 30,058,829
bytes with root SHA-512
`b1e5c143f7abf052ce2b9a24738db944d434b6bf6595ea0aaf2211258bb32c6be24602dcfb01a218b5fcdb2ebc0043b1c4e5b53d7dccb608558968238f782691`.
Both artifact reports embed the identical inventory. The inventory covers the
transaction/native/wallet dependency closure and both formal source trees;
root design documents, `docs/` and `.agent/` are outside that inventory.

Each generator ran in a separate process with fresh operating-system
randomness. The retained proofs, wire salts, DECS transcript roots, generation
run identifiers and process identifiers differ. Both retained binaries then
ran `verify-v5` against both bundles: all four commands returned success.
Both binaries also ran `verify-chain` and emitted byte-identical results.
The retained `retained-chain-verification.json` is 4,492 bytes with SHA-512
`e05eda7d359b6b4c881168bbe2129355b38b2ba10c307ab3928a6506dd01870e273953b74c6e27925de73eb7f9f26bfcfb51ef385d71fb7f7939e96aa388591a`.

For each proof the generator recorded successful source-factory verification,
hash-manifest readback, exact canonical transport and PendingAction readback,
3 relation mutations, 8 proof/input mutations, 7 transport mutations,
15 PendingAction mutations, 10 transport-stage checks and a ciphertext
mutation. The identical SMZ9 proof byte string is preserved in the native
leaf, RPC envelope, SCALE arguments and complete pending action. The private
witness was never written to the retained bundle.

The reproducible cross-verification commands, run from the repository root,
are:

```sh
artifact_root=.agent/artifacts/smallwood-poseidon2-v8/hgv8rp03-b1e5c143f7abf052
primary_bundle="$artifact_root/retained_proof_primary/smz9-fe2cfc6917b54fda12c24fc8"
independent_bundle="$artifact_root/retained_proof_independent/smz9-fe942e23e9ac2d0ec2a07440"
for artifact_build in build-a build-b; do
  artifact_verifier="$artifact_root/generator-binaries/$artifact_build/smallwood_poseidon2_v8_artifact"
  "$artifact_verifier" verify-v5 "$primary_bundle"
  "$artifact_verifier" verify-v5 "$independent_bundle"
  "$artifact_verifier" verify-chain "$primary_bundle" "$independent_bundle"
done
```

The generator recomputes the live source inventory. Replaying these commands
after covered source changes must not be described as verification of the
same release source snapshot without examining that change.

## Resource and claim boundary

One compiler or prover ran at a time. The data volume had about 31 GiB free
before execution and 30 GiB afterward. The fresh build and diagnostic scratch
occupy about 310 MiB; the retained bundle occupies about 8.1 MiB. A process
sample during the independent proof showed about 5.43 GiB RSS; this is an
observation, not an exact peak measurement. The primary generator finished
successfully and published its readback-verified bundle, but its optional
`/usr/bin/time -l` wrapper returned an error after generation because the
sandbox denied `sysctl kern.clockrate`. A subsequent direct `verify-v5`
returned success. The independent run used `time -p` and returned success.

This closes fresh repaired-relation proof generation and deterministic
artifact verification for the recorded source snapshot. The report's
`node_pending_action_lifecycle` field concerns exact carrier construction and
readback; the native RPC/relay/mining/restart/reorg/fresh-import harness has its
own receipt. These local builds and generation records remain informational
provenance, without a hermetic attestation. Adaptive whole-view privacy,
accepted-byte knowledge soundness, universal Rust/Lean refinement and
production authorization retain their independent evidence requirements.
The artifact and chain reports keep production capability disabled.

## Native lifecycle receipt

The repaired candidate was subsequently sealed as
`.agent/artifacts/smallwood-poseidon2-v8/retained-artifact-manifest.candidate-b1e5c143f7abf052.json`
with SHA-512
`b22e0df0a68189b75bd28fe79cb26b92a4161de18608df83ea842210223e33b621e1b6c425d6084bcfc41747cc51a29f9f66756fac18b9694c9da0115ffae897`.
The explicit candidate lifecycle test passed: one passed, zero failed, zero
ignored, 738 filtered out, 42.23 seconds. Its test build took 2 minutes
19 seconds. The exact invocation was:

```sh
env CARGO_BUILD_JOBS=1 RAYON_NUM_THREADS=2 \
  HEGEMON_TEST_RETAINED_SMZ9_MANIFEST_PATH=.agent/artifacts/smallwood-poseidon2-v8/retained-artifact-manifest.candidate-b1e5c143f7abf052.json \
  cargo test --locked --offline -j1 -p hegemon-node \
  --features poseidon2-v8-retained-test-support \
  native::poseidon2_v8_verifier::tests::retained_rp03_two_coinbase_chain_survives_rpc_relay_mining_restart_reorg_and_fresh_sync \
  --lib -- --ignored --exact --nocapture \
  >/private/tmp/hgv8rp03-repaired-proof-4a0acb9b.MM0MEA/lifecycle.log 2>&1
```

The resulting log has SHA-512
`f4aa02b799c22330daf43182e44b03af3de3ad5a9b6431d717bec89a376ce1481f07595162af50a7e31a5dcaacde7913c4f9bf085d1d97081af75b0ad66bdb95`.
After the lifecycle, this candidate verification command also passed with the
same source inventory, 29 payload files and 8,419,305 payload bytes:

```sh
python3 scripts/construct_smallwood_poseidon2_v8_retained_manifest.py verify \
  --artifact-root .agent/artifacts/smallwood-poseidon2-v8/hgv8rp03-b1e5c143f7abf052 \
  --manifest .agent/artifacts/smallwood-poseidon2-v8/retained-artifact-manifest.candidate-b1e5c143f7abf052.json
```

The test at `node/src/native/poseidon2_v8_verifier.rs:1938` exercises these
specific boundaries:

| Boundary | Executed path and assertion |
| --- | --- |
| Wallet and RPC | The actual wallet JSON request helper feeds the native request decoder and `validate_and_stage_action`. Reconstructed inline arguments, encoded action and persisted mempool row exactly equal the retained bytes. |
| Peer and mempool | The independent action passes the production peer PendingAction decoder and `stage_relayed_pending_action`. The staged action and prepared mining action exactly equal its retained bytes. |
| Mining and persistent blocks | Native `prepare_work`, `mine_native_round` and `import_mined_block` mine the two source coinbase notes and both sibling proof blocks at development difficulty. Prepared actions and stored block action bodies compare exactly with the retained encodings. |
| Reorganization | The independent sibling becomes canonical through its height-four extension; the primary branch wins back at height five. The canonical height-three body switches between the two exact retained actions and restores the original primary bytes. |
| Reopen and fresh import | The primary node is dropped and reopened on its sled database; a separate fresh database receives complete announced blocks. Both recover the primary height-five tip and the exact original height-three body. Reopen also checks the exact original native leaf. |
| Typed state | A separate store fixture counts real verifier calls for preflight, application, each reorganization and fresh replay. It checks two source notes, four notes after the spend, spent nullifiers, canonical proof count one, unchanged disabled-stable state, and exact row equality between restarted and freshly replayed stores. |

The source verification path is concrete. The native connector calls
`verify_smallwood_poseidon2_v8_candidate` on the decoded proof at
`node/src/native/poseidon2_v8_verifier.rs:725`. The exact-leaf test wrapper
checks the supplied native leaf against the retained byte string before
delegating to that connector. Native startup calls
`reconcile_poseidon2_v8_canonical_history`; its loop at
`node/src/native/node_impl.rs:4072` replays every canonical block from genesis
through the source verifier into a temporary typed store, then compares the
durable typed rows with that replay. The separate typed-store reopen operation
only reloads rows; its later reorganization and fresh-replay checks explicitly
invoke the source verifier.

The negative checks distinguish their rejection boundaries. A proof-body
mutation is preserved by wallet packaging and RPC decoding and then rejected
with `SMZ9 proof rejected`; the mempool remains empty. A corrupted peer action
fails exact decoding. A fresh-import block-body mutation is rejected by its
action-root, identity or decoding check before the valid original block is
imported. The latter two checks are carrier-integrity evidence rather than
additional cryptographic proof-rejection evidence.

This is an in-process integration test using isolated sled databases. It does
not open an HTTP server, exchange libp2p messages, run locator/body-chunk
synchronization, or restart an operating-system node process. The wallet path
uses its actual request-construction helper with an explicit test context;
the fixture inserts the two fixed miner-local coinbase actions through test
hooks. A temporary test binding enables the dormant route inside the test,
while the actual source capability remains absent. Teardown explicitly checks
that both action-10 transaction authoring and action-11 mint-source authoring
return `Denied`. The fixture covers the two-input/two-output single-key spend
with disabled stablecoin mode; it does not test enabled stable mint/burn,
other authorization modes, an activated release, or external-network operation.
