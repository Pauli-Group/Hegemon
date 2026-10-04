# RP05/SMZA implementation boundary

Status: implementation-boundary map for the current source tree, not a new
security theorem, a Rust-to-Lean refinement proof, or activation authority.
This document records where current serialized inputs are parsed and checked,
what source-owned code the native route calls, and which steps remain trusted.
It is intentionally narrower than a claim about the compiler, operating
system, node lifecycle, or universal security of the proof system.

## Acceptance path in the current source

The additive q38 lane has three distinct wire identities: outer `SWP8LC03`,
native leaf `HGV8TX03`, and inner proof `SMZA`. The transport module pins the
profile/domain identifiers (9/5) and limits (164,113 proof bytes; 169,547
inline action bytes); these are separate from the semantic relation. The
exact native-leaf/envelope/inline decoders bind expected network and relation
context through `Poseidon2ProductionExpectedContext`
([poseidon2_production_transport.rs](../../protocol/shielded-pool/src/poseidon2_production_transport.rs:42)).

The native verifier selects SMZA only on its explicit SMZA route. It contextually
decodes the exact leaf before entering the proof engine, reconstructs a 120-word
statement plus seven relation/balance limbs, checks parent height against the
block parent, and calls the SMZA frontend verifier
([poseidon2_v8_verifier.rs](../../node/src/native/poseidon2_v8_verifier.rs:1624)).
The outer parser's decoded slices borrow the input bytes; the proof is not
re-serialized between carrier decoding and verifier invocation.

At the frontend, `validate_verifier_input` rejects zero relation identity,
noncanonical/out-of-range public fields, structurally invalid statements, and
any relation/balance binding that differs from recomputed action intent. The
source relation factory checks the checked-in program digest and reconstructs
the adapter from that statement. The SMZA verifier then checks relation
contract and equality with the input, exact relation digest, `SMZA` magic,
activity-derived size cap, the canonical 1104-byte/138-word preamble, and calls
the local accepted-run audit. The preamble is reconstructed from verifier-owned
network, relation digest, statement, balance binding, profile 9 and domain set
5; callers do not supply a separate transcript prefix
([smallwood_poseidon2_v8_frontend.rs](../../circuits/transaction/src/smallwood_poseidon2_v8_frontend.rs:807)).

The inner proof decoder reads the magic into an exact wire identity, applies
the SMZA 164,113-byte cap, decodes bounded typed structures, and rejects
noncanonical field words (`u64 >= FIELD_ORDER`). The full-byte decoder rejects
any unconsumed trailing bytes; the profile-specific trace decoder additionally
requires the SMZA identity. These checks establish this source parser's
canonical decoding behavior, not a theorem that every Rust execution refines
the Lean post-parser field-view model
([smallwood_engine.rs](../../circuits/transaction/src/smallwood_engine.rs:2590),
[decoder](../../circuits/transaction/src/smallwood_engine.rs:3136)).

## Ciphertext framing and statement projection

The HGV8 statement commits each active output ciphertext in six public limbs at
statement words `[32,44)`. Parsing requires exactly one fixed-size ciphertext
for each active output, in output-slot order; inactive slots must be absent.
`validate_against_statement` hashes the exact ciphertext bytes and compares
the six derived words to those statement positions
([smallwood_poseidon2_v8_types.rs](../../circuits/transaction/src/smallwood_poseidon2_v8_types.rs:1597)).

The source hash is conventional RFC 7693 BLAKE2b-384, domain-separated with
`hegemon.transaction.ciphertext-hash.v2`. Its source frame is
`hegemon.blake2b-384.frame-v1 || LE64(domain_len) || domain ||
LE64(part_len) || bytes`. The 48 digest bytes are split into six big-endian
`u64`s, each converted with `Felt::from_u64` (reduction modulo the Goldilocks
field modulus `p = 2^64 - 2^32 + 1`) and then serialized as six canonical
field limbs. The Rust vector test checks the KAT input, complete frame, digest,
six-word projection, and explicit false refinement-status fields
([hash384](../../crypto/hash384/src/lib.rs:451),
[ciphertext projection](../../circuits/transaction-core/src/hashing_pq.rs:245),
[semantic-refinement KAT](../../circuits/transaction/src/smallwood_poseidon2_v8_semantic_refinement.rs:740)).

What is checked is the concrete Rust framing/hash/projection plus this KAT and
typed round-trip/mutation tests. The commitment's binding target is the exact
composed function from framed ciphertext bytes to the six field limbs:
`C(c) = Project_p(BLAKE2b-384(Frame_v1(domain_v2, c)))`. A collision bound
must cover `Adv_bind^C(A) = Pr[c != c' and C(c) = C(c')]` for the adversary's
chosen ciphertext pairs, under the exact frame, domain, and six-limb
projection. Any composed security epsilon must allocate and bound this
advantage. It is not sufficient to cite raw BLAKE2b-384 collision resistance
alone: each 64-bit digest chunk is reduced modulo `p`, so distinct 48-byte
digests can map to identical six-limb commitments. The security accounting
must bound the collision advantage of the exact framed-and-projected function
(equivalently, account for both a raw digest collision and a distinct-digest
projection collision); this review does not provide that bound or claim a
384-bit binding level for the projected commitment.

The reviewed Lean relation treats RFC 7693 BLAKE2b-384 as an opaque symbol,
and repository status remains
`exact_primitive_interpretation_refinement_proved = false`. Independently of
the collision/binding assumption, the current evidence does not prove that the
Rust framing, BLAKE2b implementation, digest-to-field reduction, and canonical
limb serialization equal the Lean function for all ciphertexts. Primitive
implementation correctness/refinement is a separate trusted boundary; a KAT
does not prove universal implementation refinement.

## Correspondence evidence and residual trust

The current correspondence evidence is finite and source-specific:

- source-owned transport decoders distinguish SWP8LC03/HGV8TX03/SMZA and check
  exact grammar, lengths, context and profile identity;
- Rust inner-wire codec tests check SMZA round-trip, historical identity
  rejection, size caps and trailing-byte rejection;
- typed statement/ciphertext tests check canonical field parsing, all sixteen
  activity masks, exact ciphertext lengths, activity mismatches and digest
  mutation rejection;
- the semantic-refinement vector test checks one independently specified
  ciphertext KAT's frame, digest and six-word projection;
- the native acceptance route reconstructs the source adapter and invokes the
  production-shaped SMZA frontend/local audit on the unchanged decoded proof
  slice.

These provide implementation and differential evidence, not universal Rust
semantics extraction or an accepted-Rust-proof-to-Lean-acceptance theorem. The
reviewed Lean endpoints start at a post-Rust-parser field view; they do not
define the serialized `SmallwoodProof` parser or prove native Rust acceptance
refines the Lean verifier. The Lean digest is opaque. Compiler behavior,
platform behavior, and lifecycle preservation are outside this boundary map.
See the independent review's public F1/F4 dispositions in
[RP05_INDEPENDENT_REVIEW_RESOLUTIONS.md](RP05_INDEPENDENT_REVIEW_RESOLUTIONS.md).

The semantic-adequacy metadata has two intentionally distinct identities.
The generated Lean receipt/vector remains schema and target v1 for legacy
`HGV8RP03`, with a 721-word typed witness. The current Rust source-local receipt
uses schema/target v2 for `HGV8RP05`, including its 740-word witness and
successor five-word policy / seven-word signer-tag semantics. The legacy vector
does not specify or certify those RP05 changes. The focused Rust tests pin both
IDs, assert their difference (rather than skipping a mismatch), compare shared
primitive KATs only, and separately check the current source's decoder/status
invariants. This test split is not a refinement proof; a current-RP05 Lean
semantic target/vector is still absent.

The remaining end-to-end production gates also remain separate: independent
security review, unchanged-carrier lifecycle/identity evidence, and release
authorization. Passing these implementation tests or documenting this map
does not select a production capability.

## Focused reproducible tests

No new test file is needed for this boundary: focused source tests already
exercise the specified cases. From the repository root, run:

```sh
cargo test -p transaction-circuit smza_profile_codec_projection_and_historical_rejection_are_exact
cargo test -p transaction-circuit strict_zk_wire_rejects_arbitrary_opening_counts_before_proving
cargo test -p transaction-circuit inline_ciphertexts_roundtrip_and_bind_all_sixteen_masks
cargo test -p transaction-circuit inline_ciphertext_shape_and_length_mutations_fail_closed
cargo test -p transaction-circuit lean_generated_semantic_adequacy_receipt_matches_rust_status
cargo test -p transaction-circuit current_rp05_source_receipt_remains_separate_and_fail_closed
cargo test -p protocol-shielded-pool smza_framing_rejects_cross_profile_context_and_noncanonical_fields
cargo test -p protocol-shielded-pool smza_framing_roundtrip_maximum_all_activity_masks
```

These are ordinary focused unit-test commands and do not require proof
generation or the retained-artifact feature. They should reuse the checkout's
compatible Cargo target directory. The receipt-identity test changes are
test-only; unchanged relation/proof/lifecycle inputs are assessed separately
from the changed source inventory rather than relabeling historical runs as
fresh runs.
