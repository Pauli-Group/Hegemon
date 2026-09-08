# HGV8RP03 nonlinear metadata-order repair

Date: 2026-09-08 UTC. This repair corrects descriptor order, not executable
constraints. It changes the program identity and does not activate a route.

## Exact change

The source builder interleaves each input's 32 direction bits and asset root,
each output's asset root and six inactive-ciphertext roots, and each input's
effective PRF and four key roots. The metadata exporter previously grouped
these families. Split spans now follow the builder, with each family's local
counter continuing across its spans.

An independent binary parser checks exact framing and consumption of all nine
sections and all 830 nonlinear descriptors. Only section 4 changes. Exactly
45 records change at `63..95`, `98..104`, and `243..247`: six family labels and
45 local indices, consisting of six records changing both fields and 39
local-index-only changes. Global indices, coordinates, family multiplicities,
all executable expressions/roots in section 8, and all CSR records in section 9
remain byte-identical. All other sections are also byte-identical.

Both programs are exactly 853,429 bytes. Their SHA-512 identities are:

- Before: `180fca50376f7573cacedfb5465a0b4d6bf5c61637152035a682d21038016d2239e2f8b50605f36baa635038348dc984197d6df29347e17e1150c24ff737de84`.
- After: `7e50eba07d84433a53a6c85ed2b3efecbeff103ca402bb931831e1598e6c9ab8fa138c9b2f0cb9d21bf2bf044b50d4d057ae0bb12e4def00ec52765245cf9e17`.

The native relation ID is the first 48 digest bytes. HGV8RP03 format magic,
SMZ9/profile 6, geometry, primitives and wire grammar do not change. Because
the digest binds the whole program, unchanged executable constraints do not
make old proof bytes proofs of the new identity.

## Regression and regenerated records

The regression checks actual expression witness rows before metadata at 90
input, output and authorization roots. Before the fix it fails at actual root
63: metadata says direction bit 32, but the expression references input asset
zero. After the fix it passes. Seven program tests cover exact vectors, source
bytes, descriptor inventory, executable-field mutations, framing, CSR cursor
mutations and the digest known answer. The hash-kernel vector and executable-ZK
report tests also pass: ten targeted Rust tests in total.

The source emitter produces the corrected binary. Regeneration changes only
the expected digest and relation-ID fields in the Lean transcript/kernel
vectors and the two Rust reports. The semantic-adequacy vector is byte-identical.
Only the generated components file and descriptor certificate chunks 00/01
change; the other 46 certificate files remain byte-identical. The generator
self-test and exact generated-file check pass.

The diagnostic source report remains 136,119 bytes, SHA-512
`5346d68e30c7ec99d197669679159af777ae7663029e22fc84da8fbf5e353b1829b4f4368b6449510b25bbf1e1022281891a114f51783148e2423c538e0b5110`.
The executable-ZK report remains 4,230 bytes, SHA-512
`e89ff29b047d85c6121689c4d298f031141d2dac6452f182d5d8d53cdd4ef7694c8616909ade6be95bcf1b1e06e98dd25b13df79bd7372be9a5af0500fe9015b`.
Both source-rebuilt exact `--check` commands pass. Their authority fields,
simulator proof/query/table hashes and all non-identity data are unchanged.

All 21 retained-constructor tests pass. Historical tests load their frozen
manifest and recover `smallwood_poseidon2_v8_program.rs` from the recorded
generation commit with `git show`, then check its exact length and SHA-512
against the retained source inventory. They use the fixture's own binary,
not current source bytes labeled as historical. A separate test recognizes
the corrected exact source profile and rejects an old-profile substitution.
The successor-authorization fixtures also pass; the registry remains empty.

The first full formal rebuild rejected an old theorem that asserted the four
incorrect descriptors were still current. Its replacement,
`exact_early_descriptor_root_alignment_examples`, checks the corrected records
at 63/95/98/104, keeps the same executable node IDs 916/980/1006/1023, and
explicitly rejects all four old records. The credited inventory replaces that
one name; its count stays 1,472. The failed run and pre-edit source are retained.

## Reproduction and evidence

Commands run from the repository root with one build at a time:

```sh
cargo run --locked --offline -j1 -p transaction-circuit --example smallwood_poseidon2_v8_artifact -- program /tmp/metadata-program.bin
cargo test --locked --offline -j1 -p transaction-circuit --lib smallwood_poseidon2_v8_program::tests:: -- --test-threads=1
cargo test --locked --offline -j1 -p transaction-circuit --lib smallwood_poseidon2_v8_semantics::tests::nonlinear_descriptor_order_matches_actual_root_rows -- --exact
python3 scripts/test_construct_smallwood_poseidon2_v8_retained_manifest.py
python3 scripts/test_check_transaction_proof_successor_authorization.py
env LEAN_NUM_THREADS=1 bash scripts/check_formal_crypto.sh
```

The evidence directory is
`.agent/artifacts/smallwood-poseidon2-v8/metadata-order-7e50eba07d84433a/`.
It retains the before/after binaries, independent comparison scripts and
receipts, old/new JSON records, negative and positive logs, and a byte/hash
manifest. `check_rust.sh` records all ten tests and both report checks.
The post-metadata full formal gate passed on 2026-09-08 at 17:03 UTC: all
3,066 build jobs, all 1,472 credited-declaration audits under the kernel axiom
allowlist, and the canonical wire checks. Its final log SHA-256 is
`37e71135134ec82186b948b02aa11052cdcf324a88109cb99cfde3c503281e3e`.
Both the first failed run and final passing run are preserved; the cached
rerun followed the one explicit descriptor-control correction above.

## Remaining work

No retained honest proof or lifecycle receipt is generated for the corrected
identity by this repair. Prior `b1e5c143f7abf052` and `cee3cb81` receipts stay
bound to their original source and program. The complete security endpoints,
remaining source-semantic and Rust-refinement obligations, independent review
and release authorization are unchanged. The earlier 1,472-declaration archive
is preserved as the pre-metadata checkpoint, not relabeled as a new receipt.
