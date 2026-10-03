# ProveKit stable v1 production architecture screen

Date: 2026-08-22  
Mode: bounded source-only audit; no clone, build, dependency fetch, or recursive Groth16 path  
Decision: **disqualified; production remains fail-closed**

World Foundation ProveKit's stable nonrecursive path is a real generic-R1CS proof stack, not a mock-up: it combines a Spartan-style R1CS sumcheck with two masked zkWHIR instances. It is nevertheless not a qualifying Hegemon architecture. No exact HX448C02 transaction relation, whole-view complete-ZK theorem, finite-QROM composition, canonical bounded consensus parser, end-to-end Hegemon binding, or same-relation retained proof artifact exists in the audited sources. `same_hx448c02_proof_bytes` is therefore `null`, and this screen records no proof-size win.

Two independent security gates already disqualify the stable configuration. Its SHA-256/SHA3-256 commitment surfaces have only a generic quantum collision ceiling of `256 / 3 = 85.33333333333333` bits. Separately, the primary Duplex Sponge Fiat-Shamir paper analyzes a classical ideal-permutation setting and explicitly leaves security against superposition permutation queries open. ProveKit's SHA-256 Spongefish bridge is itself labelled heuristic by its source.

## Exact upstream authority

The audit authority is the peeled commit for the official [`v1.0.0` release](https://github.com/worldfnd/provekit/releases/tag/v1.0.0):

- annotated tag object: `add654221a069ac1412caa747777e781e6901474`
- peeled release commit: `253113f4be6bc256551a43fa56084e84af2db013`
- publication time: `2026-05-12T10:31:21Z`
- release assets: none
- `v1` branch head observed on 2026-08-22: `9b2a6f37c67691eab4b0cec6c35e35c520e93285`
- [release-to-branch comparison](https://github.com/worldfnd/ProveKit/compare/253113f4be6bc256551a43fa56084e84af2db013...9b2a6f37c67691eab4b0cec6c35e35c520e93285)

The release pins `provekit-whir 0.1.1` with Cargo checksum `35334259c6ad5b1287ecef6bfb3deb3dbb963c9366091951316bdb33c2080fe6` and `provekit-spongefish 0.1.0` with checksum `95a705ff6cb8bc4566a2d1a9f665243db958cbd90a852c3eef0dcc8dc8879ce5`. The later `v1` changes do not replace those dependencies or the audited common/verifier/configuration surfaces; they mainly remove temporary compiler allocations and change mobile, WASM, benchmark, and dependency plumbing. All normative findings below use the release commit, not moving-branch content.

## Gate verdicts

| Required gate | Result | Source-grounded reason |
| --- | --- | --- |
| Exact full HX448C02 relation | Fail | No 2-input/2-output, all-16-mask, stablecoin, all-authorization-mode Hegemon circuit or refinement is present. |
| Complete zero knowledge | Fail | A substantive bounded-query mask construction is implemented, but no exact whole-view simulator/theorem covers both transcript streams, public wrapper, abort/retry behavior, and parser. |
| Composed at least 128-bit PQ/QROM | Fail | 256-bit collision binding caps at about 85.33 generic quantum bits; no finite-query QROM ledger exists; DSFS superposition-query security is open. |
| Exact verifier/consensus binding | Fail | The generic scheme binds a relation digest and public-input digest, but no exact Hegemon parser/statement/action/network/version/domain or semantic refinement exists. |
| Canonical bounded proof parser | Fail | Transcript EOF checks exist, but the file reader accepts two compression encodings, accepts newer minor versions, and has no compressed/decompressed/nested-vector size bounds. |
| One unchanged production proof | Fail | There is one logical ProveKit proof object, but no wallet, RPC, relay, mempool, mining, block, sync/reorg, or fresh-node Hegemon integration evidence. |
| Measured same-HX448C02 bytes | Fail | The release has no proof assets and no HX448C02 artifact. The comparable byte count is `null`. |
| Production release manifest | Fail | No Hegemon mutation/restart/formal/refinement manifest exists. |

## Relation capability: generic backend yes, shipped full relation no

[`provekit/common/src/lib.rs`](https://github.com/worldfnd/ProveKit/blob/253113f4be6bc256551a43fa56084e84af2db013/provekit/common/src/lib.rs) aliases the proof field to `ark_bn254::Fr`. [`provekit/common/src/r1cs.rs`](https://github.com/worldfnd/ProveKit/blob/253113f4be6bc256551a43fa56084e84af2db013/provekit/common/src/r1cs.rs) exposes sparse A/B/C constraints and witness allocation, so the backend can represent arbitrary R1CS over that prime field. The direct, nonrecursive path does not invoke an elliptic-curve commitment or pairing.

That generic representability is not an exact transaction implementation. The stable Noir compiler accepts arithmetic `AssertZero`, a limited memory path, and only `RANGE`, `AND`, `XOR`, `Poseidon2Permutation`, and `Sha256Compression` black boxes. Other black boxes and opcode/index forms explicitly fail or are unimplemented. There is no BLAKE2b black box and no exact Boolean RFC 7693 BLAKE2b-384 Hegemon relation. A hand-built Boolean R1CS might be possible, but possibility is not a port, a verifier refinement, or proof evidence.

The R1CS relation identifier is `SHA3-256(postcard(R1CS))`. The scheme configuration carries that digest, and the transcript binds the configuration plus a digest of the public inputs; the verifier also checks the sumcheck's public-input contribution. This is useful generic binding. It does not instantiate Hegemon's parser, action, network, version, domain, ciphertext, balance, nullifier, Merkle, or intent bindings. The source-only audit also did not locate a top-level recomputation asserting that the trusted scheme's stored R1CS digest equals a fresh serialization of its supplied matrices, so relation-artifact consistency remains part of the trusted verifier configuration.

## Nonrecursive Spartan/WHIR stack and assumptions

[`provekit/r1cs-compiler/src/whir_r1cs.rs`](https://github.com/worldfnd/ProveKit/blob/253113f4be6bc256551a43fa56084e84af2db013/provekit/r1cs-compiler/src/whir_r1cs.rs) configures the release path as follows:

- minimum `log_num_variables = 14`
- `security_level = 128`
- `pow_bits = 10`
- `unique_decoding = false`, selecting Johnson-bound list decoding
- starting log inverse rate `2`, hence rate `1/4`
- initial and subsequent folding factors `3`
- batch size `1`
- WHIR `hash_id = SHA2`

The source's intended accounting is 118 algebraic bits plus 10 grinding bits, and its tests exercise the dependency's classical security estimator. This is not a post-quantum composition. The PCS uses interleaved Reed-Solomon encoding, out-of-domain and in-domain queries, round-by-round WHIR/STIR-style proximity checks, and SHA-256 Merkle matrix commitments. The relevant primary references are [WHIR](https://eprint.iacr.org/2024/1586) and [STIR](https://eprint.iacr.org/2024/390).

The recursive Groth16 wrapper is deliberately excluded. It is pairing-based and ineligible under Hegemon's no-ECC/no-pairing constraint; none of its size or security properties enter this comparison.

## Zero-knowledge claim boundary

The pinned [`provekit-whir 0.1.1` zkWHIR module](https://docs.rs/crate/provekit-whir/0.1.1/source/src/protocols/whir_zk/mod.rs) implements more than witness obfuscation. Its code labels the construction “zkWHIR 2.0 — Alternative Randomness Sampling,” commits a masked witness polynomial in one WHIR instance, commits mask/blinding polynomials in a second instance, derives masks from a transcript-bound CSPRNG, and sizes masking degrees from a bounded-query leakage expression. The [committer source](https://docs.rs/crate/provekit-whir/0.1.1/source/src/protocols/whir_zk/committer.rs) and the official [bounded-query design note](https://github.com/worldfnd/ProveKit/blob/253113f4be6bc256551a43fa56084e84af2db013/playground/sage/fri-and-friends/Zero%20Knowledge%20for%20WHIR.md) support calling this a substantive masking construction.

They do not support a production complete-ZK claim. No primary theorem for this exact two-WHIR construction was identified. No retained simulator/certificate covers the whole accepted proof view: `NoirProof`, `narg_string`, the separate `hints` transcript, public inputs, statement/configuration, parse behavior, malformed proofs, or adaptive abort/retry. The official design note itself scopes its statement to a bounded-query model. Accordingly, `whole_view_complete_zk_proved`, `adaptive_qrom_zero_knowledge_proved`, and `hegemon_complete_zero_knowledge` are all false.

## Exact hash and transcript surface

| Surface | Stable v1.0.0 construction | Width/status |
| --- | --- | --- |
| R1CS relation identifier | SHA3-256 over postcard R1CS | 32 bytes / 256 bits |
| Protocol identifier | SHA3-512 over CBOR configuration | 64 bytes / 512 bits |
| Optional session identifier | SHA3-256 over CBOR session | 32 bytes; stable ProveKit prove/verify path supplies no session |
| Public-input instance | SHA-256 over concatenated little-endian field representations, reduced into `ark_bn254::Fr` | 32-byte serialized field, about 254-bit field capacity |
| Fiat-Shamir transcript | `provekit-spongefish` SHA256 bridge | 32-byte chaining state; arbitrary-length indexed squeeze; source marks bridge heuristic |
| WHIR row/Merkle commitments | SHA-256 | 32-byte leaves/nodes; same hash ID for rows and internal nodes |
| WHIR proof of work | SHA-256 | 10 configured grinding bits |

The exact transcript setup is in the versioned [`provekit-whir` transcript source](https://docs.rs/crate/provekit-whir/0.1.1/source/src/transcript/mod.rs). The matrix commitment, Merkle, and digest engines are in the versioned [`matrix_commit.rs`](https://docs.rs/crate/provekit-whir/0.1.1/source/src/protocols/matrix_commit.rs), [`merkle_tree.rs`](https://docs.rs/crate/provekit-whir/0.1.1/source/src/protocols/merkle_tree.rs), and [`digest_engine.rs`](https://docs.rs/crate/provekit-whir/0.1.1/source/src/hash/digest_engine.rs). The SHA-256 bridge and its security qualification are in [`provekit-spongefish 0.1.0`](https://docs.rs/crate/provekit-spongefish/0.1.0/source/src/lib.rs) and its [hash instantiations](https://docs.rs/crate/provekit-spongefish/0.1.0/source/src/instantiations/hash.rs).

## PQ/QROM no-go

For an ideal `n`-bit hash, generic Grover preimage work is at most `2^(n/2)` and Brassard-Høyer-Tapp collision work is `O(2^(n/3))`; see the primary [BHT collision paper](https://arxiv.org/abs/quant-ph/9705002). For every 256-bit commitment/binding surface above:

```text
generic quantum preimage ceiling = 256 / 2 = 128 bits
generic quantum collision ceiling = 256 / 3 = 85.33333333333333 bits
```

The collision ceiling alone rules out a composed strict-PQ128 claim whenever commitment binding relies on those 256-bit hashes. Even the preimage ceiling is exactly 128 before concrete loss, multi-target effects, and union/composition, not greater than or equal to 128 after them.

The 10-bit proof-of-work term has at most a 5-bit generic Grover ceiling. Even granting the source's additive `118 + 10` split as a heuristic, replacing 10 with 5 yields only `123` bits before all other losses. This arithmetic is an upper-bound diagnostic, not a security reduction.

More fundamentally, no finite-QROM theorem was found for the composed PCS/IOP, custom zkWHIR layer, Duplex Sponge Fiat-Shamir, SHA-256 bridge, grinding, and union of all failure events. The primary [Duplex Sponge Fiat-Shamir paper](https://eprint.iacr.org/2025/536.pdf) gives a classical ideal-permutation analysis and explicitly identifies security against superposition permutation queries as open; a ROM proof does not automatically imply a QROM proof. General QROM work such as the [QROM BCS analysis](https://eprint.iacr.org/2019/834) is not an instantiated security ledger for this code. Thus `composed_security_bits` is `null`, not 85.33 or 123, and `strict_pq128` is false.

## Proof object, parser, and consensus suitability

[`WhirR1CSProof`](https://github.com/worldfnd/ProveKit/blob/253113f4be6bc256551a43fa56084e84af2db013/provekit/common/src/whir_r1cs.rs) embeds both `narg_string` and `hints`, and [`NoirProof`](https://github.com/worldfnd/ProveKit/blob/253113f4be6bc256551a43fa56084e84af2db013/provekit/common/src/noir_proof_scheme.rs) packages public inputs with that proof. This is one logical proof object; neither transcript is a validity sidecar. The [verifier](https://github.com/worldfnd/ProveKit/blob/253113f4be6bc256551a43fa56084e84af2db013/provekit/verifier/src/whir_r1cs.rs) checks EOF on both transcript streams, which rejects transcript suffixes at that layer.

The outer `.np` reader in [`file/bin.rs`](https://github.com/worldfnd/ProveKit/blob/253113f4be6bc256551a43fa56084e84af2db013/provekit/common/src/file/bin.rs) is not a consensus parser. Although it checks magic, format, and major version, it accepts either zstd or XZ compression, accepts newer minor versions, reads/decompresses the whole input without a compressed or decompressed maximum, and leaves nested proof vectors without consensus size limits. The library also exposes a separate base64url/CBOR representation. Consequently the stable source does not define one canonical bounded byte string suitable for hostile network consensus input.

No source demonstrates the same bytes moving unchanged through Hegemon wallet → RPC → relay → mempool → mining → block → sync/reorg/fresh node. No negative mutation/restart suite or fail-closed release manifest connects ProveKit verification to Hegemon consensus. Generic self-containment of the proof object does not satisfy that production gate.

## Proof-size comparison

There is no comparison to make. The official release has no retained proof asset, and neither release source nor the stable branch contains an exact HX448C02 relation/proof artifact. Generic example or benchmark sizes would compare different relations and configurations. Therefore:

```text
same_hx448c02_proof_bytes = null
retained_same_relation_proof_artifact = null
proof_size_win = false
architecture_winner = null
```

Proof-byte optimization must not begin until the exact relation, complete-ZK, composed-PQ/QROM, exact-verifier, canonical-parser, and production-transport gates pass.

## Reproduction and source manifest

The adjacent `ledger.json` retains every decisive Boolean, exact pin, dependency checksum, source URL, and release-file SHA-256. The dependency-free checker validates the fail-closed invariants and can optionally refetch only the pinned official release files:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/provekit-architecture-screen/check_provekit_architecture_screen.py
PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/provekit-architecture-screen/check_provekit_architecture_screen.py --online
```

`--online` is a source-hash refresh, not a clone, build, or dependency installation. The default check is offline and deterministic.
