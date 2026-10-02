# Measured native private SHA-256 component

On 2026-10-02 the isolated K64 adapter generated and verified a genuine native strict-SMZ1 proof for `exists secret:[u8;32]. SHA256(secret)=public_digest`. Public context is transcript-bound opaque bytes, not authenticated consensus or authorization. No fresh OS preimage or assignment is retained. This is not a full HTLC proof, production transaction, RP05 profile, production-compatible carrier or composed PQ128 qualification.

## Actual retained run

Evidence directory: `/private/tmp/hegemon-htlc-native-proof-20261002-r1`.

| Check | Measured result |
| --- | --- |
| Actual proof bytes | 311,938 |
| Production RP05 inner cap, unchanged | 164,113 |
| Size fit | false; exceeds by 147,825 bytes |
| Honest proving | 4.519117083 seconds |
| Same-process verification | 0.139584833 seconds; accepted |
| Fresh-process verification | 0.150546459 seconds; accepted |
| Actual unchecked invalid-witness engine path | 4.596814209 seconds; generated proof rejected |
| Changed digest/context/version/domain | all rejected |
| Changed proof byte / appended byte | both rejected |
| Wrong-secret host preflight | rejected |
| Private-input pins / auxiliary witness words | 0 / 0 |
| Source closure SHA-256 | `cd01f3d21e73952c313ca2766ca5fd4ddabc07bf7715911da531b85f0eb1a23c` |
| Toolchain | `rustc 1.91.1 (ed61e7d7e 2025-11-07)` |

The unchecked negative uses a complete correctly evaluated SHA trace for a changed secret but the original public digest. It bypasses the host equation checker and actually calls the native prover. Its retained 311,426-byte proof is rejected by the actual verifier. This tests the proof seam rather than crediting a host rejection as cryptographic verification. The separate readback process reads only `statement.json` and `claim.smz1`, with no preimage or assignment parameter.

The exact actual profile is Goldilocks/K64/degree3/rho5/open5/beta2/N1048576/q23/eta5/PoW0/disjoint-coset/64-byte tapes/SHA-512. It lowers 55,466 canonical SHA wires into 4,159 rows and 266,176 values. There are 1,730 nonlinear polynomial batches and 210,968 linear equations: 210,688 occurrence copies, two constants, 256 public digest pins and 22 canonical padding pins. Canonical row Boolean equations constrain all 55,488 padded bits. Partial gate batches repeat a real valid gate.

Actual proof SHA-512:

`5520c31c32e42b0b96af6af88f7198dd7d54a3eae32a49b50ec2817112ab58565850509a84382a80fa1273f81d393f79fcf7a2921d3cee112b7abfaafac2b28e`

Retained file SHA-256 inventory:

```text
b66913a66184f7fb30627752ef5daacfd6ca19700284b7c0a27baa0f33a5d9de  claim.smz1
3534f548bd212f4ab742c5f0ff01f26a0b0369f2e92f89155b76216a337b84ca  invalid-witness.smz1
2e608ccbd544dc4ad5243786f97bf56c9d392013fc99c769bd3e4600b1737bf2  measurement.json
b55edf221052b55ac35cad6c4130c9674aaeb75f3bbe7a7dc9eb67a2927de0ca  source-closure.sha256
76360a4abc3e42151ea2cd47a92144005228c4fb37a3605208687b205b6a25c7  statement.json
da221c127b1533b03c92f39fe1d17457e5d7fcb3e52cffc1466be9d6c0852229  fresh-process-verification.json
1d9ab6e3bf6063d5102df5da32ec3b6a99b301b2b0a66fed03e502b37c859401  layout-projections.json
```

The last two JSON receipts were manually retained from the separate commands' stdout, preserving measured fields and explicitly labelling receipt capture. They contain only public fields/projections, not secret or witness values.

## Reproduction and completed checks

The separate release target is `/private/tmp/hegemon-htlc-smallwood-target-20261002` (306 MiB after checks). The parent standalone target remains 22 MiB. The coordinator allowed one Cargo job and four prover threads, exclusively, with a 16 GiB aggregate RSS limit. Peak RSS was not measured; projected allocation components below are not an observed peak. No node, production build or new dependency download was needed.

From this nested directory, the following exited zero:

```sh
CARGO_TARGET_DIR=/private/tmp/hegemon-htlc-smallwood-target-20261002 CARGO_BUILD_JOBS=1 cargo test --release --offline --locked --test binding
env RAYON_NUM_THREADS=4 HEGEMON_SMALLWOOD_TRACE=1 /private/tmp/hegemon-htlc-smallwood-target-20261002/release/hegemon-isolated-htlc-smallwood --out /private/tmp/hegemon-htlc-native-proof-20261002-r1 --exercise-invalid-engine
/private/tmp/hegemon-htlc-smallwood-target-20261002/release/hegemon-isolated-htlc-smallwood --verify-artifact /private/tmp/hegemon-htlc-native-proof-20261002-r1
/private/tmp/hegemon-htlc-smallwood-target-20261002/release/hegemon-isolated-htlc-smallwood --project-layouts
```

The output directory must be nonexistent; use a fresh directory to rerun. The binding integration test passed one test. The parent standalone crate passed eleven tests in 1.37 seconds, clippy with warnings denied and formatting checks. This includes differential SHA vectors, every-wire mutations, ordinary-verifier mutations, four packing geometries, coherent canonical/copy mutations, occurrence-only mutation, padding, wrong public digest and coherent field values 2 and p-1 rejected by Booleanity. Native facade compilation inherits 81 existing unused/deprecated warnings; no warnings-denied facade lint claim is made. The only compile repair was generated absolute path resolution of the unchanged original RNG mapping child module.

## Source-derived packing projections, not new proof runs

These are the unchanged native configuration/strict-SMZ1 serializer's conservative hints. K64's 318,914-byte hint is not the measured 311,938-byte proof. The larger packings have scalar-lowering tests only; no proof or security qualification is credited to them.

| Packing | Rows | Nonlinear batches | Linear equations | Native byte hint | LVCS rows x columns | Evaluation-table bytes |
| ---: | ---: | ---: | ---: | ---: | --- | ---: |
| 64 | 4,159 | 1,730 | 210,968 | 318,914 | 138 x 2,092 | 1,199,570,944 |
| 128 | 2,082 | 866 | 211,288 | 228,106 | 266 x 1,054 | 2,273,312,768 |
| 256 | 1,041 | 433 | 211,288 | 233,210 | 522 x 533 | 4,420,796,416 |
| 512 | 525 | 218 | 213,592 | 337,418 | 1,034 x 275 | 8,715,763,712 |

All four hints exceed 164,113 bytes. Evaluation-table bytes are `(LVCS_rows + eta) * N * 8`; they exclude tapes (67,108,864 bytes), a full binary Merkle node array (134,217,664 bytes), coefficient tables, witnesses and other scratch allocations. They are allocation projections, not measured peak RSS. Larger packing reduces witness rows but increases polynomial degree and opened/masking row costs; it does not establish a production-cap route here.

Full note/nullifier semantics, authentication and authenticated height adapters, HTLC claim/refund constraints, proof security qualification, Rust-to-Lean refinement, unchanged-byte node lifecycle, activation and Bitcoin connector remain outside this increment. No source or parameter change to production RP05 was made.

## Integrated current-source validation (2026-10-02, 09:13–09:16 UTC)

This second retained run validates the integrated checkout `/private/tmp/rp05-ci-20261001.223oOy` at HEAD `9554f71c1355d1a7c6e38c60919d8c64693e5e56`, including the newer flat-RNG source. The isolated facade's first rebuild failed with E0583 because the added RNG child `mod tapes;` resolved against the generated output directory. The coordinator authorized the minimal isolated build-generator repair: resolve both `mapping` and `tapes` declarations to their exact original source paths, preserving all original parent/child function bodies. No underlying engine or relation runtime source was changed for this validation. That build-generator repair is included in the new closure below; documentation is excluded from the closure. Earlier branch receipts above remain intact under their earlier source identity.

New public-only evidence directory: `/private/tmp/hegemon-htlc-native-proof-main-20261002-r1`.

| Check | Current-source measured result |
| --- | --- |
| Actual honest proof bytes | 311,618 |
| Unchanged production cap | 164,113; exceeded by 147,505 bytes |
| Honest proving | 4.442010959 seconds |
| Same-process verification | 0.148123542 seconds; accepted |
| Fresh-process public-only verification | 0.146205750 seconds; accepted |
| Actual unchecked invalid-witness engine path | 4.539571333 seconds; generated 311,938-byte proof rejected |
| Changed digest/context/version/domain | all rejected |
| Changed proof byte / appended byte | both rejected |
| Wrong-secret preflight | rejected |
| Source closure SHA-256 | `1d99ebafbf5208284e2eae2296f5be7a7d30f6db9ba6bc4261149f33289a125b` |
| Toolchain | `rustc 1.91.1 (ed61e7d7e 2025-11-07)` |
| Maximum resident set size | 1,565,425,664 bytes (macOS `/usr/bin/time -l`) |
| Peak memory footprint | 1,563,411,944 bytes (same command) |
| Whole honest-plus-negative command | 9.88 seconds real; 32.40 user; 0.59 system; zero swaps |

The profile, geometry and claimed relation are unchanged: K64/degree3/4,159 rows/1,730 nonlinear batches/210,968 linear equations, no private input pins or auxiliary witness words. Native byte size varies with sampled commitments/opening authentication paths; the 320-byte difference from the earlier run is not a relation/profile optimization. No fresh OS secret or witness was written or logged. The retained source inventory's 133 members were checked against current checkout bytes with `shasum -a 256 -c`, exit zero, after proof completion.

Honest proof SHA-512:

`ef90eecdbb5be4106c8496dae94a46d1042812a287d10126862a4d762e5593cac6ee7e25caff094723499626c5039f063ec4ea7675b68a827dd7bbcfd794938d`

New retained file SHA-256 inventory:

```text
c3ed7433d80dba22d61e3b6dd5819b6dd5a80b2d85c58a8143059f68e9cc1e4f  claim.smz1
8d4bfa9412fe8d5fd1a0071cce77972d98080044633d0d6aa774fe7e01bb2bb9  invalid-witness.smz1
03a846cfe8e0fa1552c7fb93ad36ba9dbfebb2ede30450b2189433b5c2918e84  measurement.json
b3839d5764c1553eab6bc88f980eae07e21c237f417644bad39b4b355669df54  source-closure.sha256
c2bde717467a81b797806ed7741c4dc1af294d069b534851b1bc1ef982d4b68e  statement.json
```

Executed from the integrated nested backend; all commands below exited zero after the one module-resolution repair:

```sh
env CARGO_TARGET_DIR=/private/tmp/hegemon-htlc-smallwood-target-20261002 CARGO_BUILD_JOBS=1 cargo test --release --offline --locked --test binding
/usr/bin/time -l env RAYON_NUM_THREADS=4 HEGEMON_SMALLWOOD_TRACE=1 /private/tmp/hegemon-htlc-smallwood-target-20261002/release/hegemon-isolated-htlc-smallwood --out /private/tmp/hegemon-htlc-native-proof-main-20261002-r1 --exercise-invalid-engine
/private/tmp/hegemon-htlc-smallwood-target-20261002/release/hegemon-isolated-htlc-smallwood --verify-artifact /private/tmp/hegemon-htlc-native-proof-main-20261002-r1
```

The binding test passed one test in 0.04 seconds after an optimized rebuild of 1 minute 2 seconds. Facade compilation still inherits 81 native warnings, with no warnings-denied facade lint claim. From the integrated parent standalone crate, all eleven locked offline tests passed in 1.37 seconds; clippy with warnings denied passed in 0.33 seconds. Formatting checks passed for both standalone crates. The exclusive heavy lane was released immediately after actual proofs and fresh-process verification; no geometry rerun or production proof build was performed.

Fresh-process receipt fields retained here from its stdout: `accepted=true`, `preimage_or_assignment_loaded=false`, `production_authorized=false`, `proof_bytes=311618`, `verify_seconds=0.146205750`, the proof SHA-512 above and the current source closure above. It loaded only the public statement and self-contained proof. This current-source roundtrip confirms the real SHA knowledge component still works after integration; it does not remove the size failure, full-HTLC integration obligations or security/release exclusions documented above.

## Final clean-source receipt (2026-10-02, 09:44–09:46 UTC)

The coordinator requested one final hygiene edit at checkout HEAD `e471ada3c5adb8f9a88c99227008ddddb56ed096`: remove exactly the extra EOF blank line from `experimental/htlc-prototype/Cargo.toml` and `proof-backend/Cargo.toml`, preserving a final newline and all manifest semantics. No engine, relation, build-generator or other runtime source changed. These manifests enter the source binding, so the final source was rebuilt and received one fresh honest/unchecked-invalid proof pair and separate public-only verification. Earlier source-pinned receipts remain preserved above.

Final public-only evidence directory: `/private/tmp/hegemon-htlc-native-proof-main-clean-20261002-r1`.

| Check | Final clean-source result |
| --- | --- |
| Actual honest proof bytes | 311,682 |
| Unchanged production cap | 164,113; exceeded by 147,569 bytes |
| Honest proving, two worker threads | 7.938981792 seconds |
| Same-process verification | 0.149195791 seconds; accepted |
| Fresh-process public-only verification | 0.147421625 seconds; accepted |
| Actual unchecked invalid-witness engine path | 8.018003750 seconds; generated proof rejected |
| Digest/context/version/domain/proof-byte/trailing-byte negatives | all rejected |
| Wrong-secret preflight | rejected |
| Final source closure SHA-256 | `749a3d82caca43978fc98b5ed3e6e352ac895732622d0e660d67e7e4a5189c04` |
| Maximum resident set size | 1,565,294,592 bytes (`/usr/bin/time -l`) |
| Peak memory footprint | 1,563,887,080 bytes (same command) |
| Honest-plus-negative command | 16.87 seconds real; 30.92 user; 0.54 system; zero swaps |

The claimed SHA component, K64 geometry, profile, toolchain and zero private-input/auxiliary-opening counts are unchanged. The longer proving time uses two worker threads rather than the preceding run's four. This is not a proof-size optimization or security upgrade. All 133 retained inventory members matched the final checkout bytes with `shasum -a 256 -c`, exit zero. The binding integration test passed one test in 0.04 seconds after an optimized rebuild of one minute; the unchanged native facade still emits 81 existing warnings. Parent logic tests were not repeated for manifest whitespace alone. Both standalone formatting checks and the baseline-wide `git diff 561095f6 --check` passed, including after the documentation append.

Final proof SHA-512:

`97a9e9c076d8fc26bfc454eb1bfc68b55df855d9e06ccaf1278c666512e4e8e5f27952830ffa82633fe0256cc867dfe4c53786b630e9bae879ef3625ff5d0503`

Final retained file SHA-256 inventory:

```text
883bfacfab36188ba030f31188160d5a8bc0a7d059203b4039b2faa853b345fe  claim.smz1
9ec1b75e44394beb0574ca123a521bc9ca409ef29560d278e42851cf7487df9e  invalid-witness.smz1
d9f88d6821c1698ba793e67dde37884d376c181182f9fee1e68029610cb7e4f3  measurement.json
5b877b4d6d5d3cec6bcbd2672ce0da032a075c74d86447ee804ddebcea43865a  source-closure.sha256
18f58cae719fbd1e5d4eaa066d7f3602a5ec19c782ce961e36e5df9df1ac1d11  statement.json
```

Completed commands from the nested backend, all exit zero:

```sh
env CARGO_TARGET_DIR=/private/tmp/hegemon-htlc-smallwood-target-20261002 CARGO_BUILD_JOBS=1 cargo test --release --offline --locked --test binding
/usr/bin/time -l env RAYON_NUM_THREADS=2 HEGEMON_SMALLWOOD_TRACE=1 /private/tmp/hegemon-htlc-smallwood-target-20261002/release/hegemon-isolated-htlc-smallwood --out /private/tmp/hegemon-htlc-native-proof-main-clean-20261002-r1 --exercise-invalid-engine
/private/tmp/hegemon-htlc-smallwood-target-20261002/release/hegemon-isolated-htlc-smallwood --verify-artifact /private/tmp/hegemon-htlc-native-proof-main-clean-20261002-r1
```

Fresh-process stdout receipt: `accepted=true`, `preimage_or_assignment_loaded=false`, `production_authorized=false`, `proof_bytes=311682`, `verify_seconds=0.147421625`, with the final closure and proof hash above. No fresh secret or assignment was retained. The heavy lane was released immediately after this validation, with no additional prover or geometry run. This final component still exceeds the unchanged production cap and does not prove HTLC authorization, timeout, note/nullifier integration, RP05 compatibility or composed PQ128 security.
