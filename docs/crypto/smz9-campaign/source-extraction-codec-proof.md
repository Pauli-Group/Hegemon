# Serialize actual source traces into bounded XOR registers


This living ExecPlan follows `.agent/PLANS.md`. The codec lane owns only `formal/crypto/HegemonCrypto/SmallWoodV8Smz9SourceExtractionCodec.lean` and this document. Its earlier mathematical research note `weighted-mca-projection-gap.md` is a separately authorized deliverable. All earlier interpolation files remain frozen. The coordinator granted one bounded global check slot; strict checking and principal axiom audits passed, and that slot has been released. No shared cache or build output belongs to this worker.

## Purpose / Big Picture


The existing coherent source instrument faithfully encodes the entire source extraction result with one bit per possible trace. That is finite but can be exponentially large. This module instead serializes the actual selected trace: each missing/budget marker, each complete raw input byte string, and each ordered child list. It proves an explicit inverse and embeds every source-label range into eight XOR bits per bounded serialized byte. The target is polynomial register length in the number of tracked targets, the source domain size, and the actual raw-query input-byte bound. A polynomial-time reversible extraction circuit is a different obligation and is not asserted.

## Progress


- [x] (2026-09-07) Read the actual `Geometry.ExtractionTrace`, `extract`, source parser, source stages, and existing one-hot instrument.
- [x] (2026-09-07) Coordinated scalar/vector label-range endpoint types with the vector owner.
- [x] (2026-09-07) Identified that wrapper parser lower bounds do not provide a useful upper input-byte bound; the codec therefore exposes actual finite-key byte bound `L` explicitly.
- [x] (2026-09-07) Drafted length-prefixed byte grammar, prefix inverse, source-derived arity/fitting proof, byte budget, fixed XOR register, and scalar/vector-compatible range embedding.
- [x] (2026-09-07) Obtained coordinator permission before starting any Lean process; used one sequential process with `-j1 -M3072`, without `-o`.
- [x] (2026-09-07 19:07 UTC) Repaired concrete elaboration and warning failures; strict checking passed with warning-as-error and automatic implicit variables disabled.
- [x] (2026-09-07 19:08 UTC) Ten principal axiom audits passed with only `propext`, `Classical.choice`, and `Quot.sound`; froze the source and released the global check slot for coordinator caching.

## Surprises & Discoveries


`sourceChildren` is a finite set, so its cardinality-two theorem does not directly bound the child list when duplicate child digests occur. The codec proves the actual `sourceNext` list length is at most two from the parsed grammar. A separate issue is raw byte length: leaves are exactly 1280 payload bytes, and internal nodes are 64 or 128 bytes, but root wrappers accept at least 96 bytes and PIOP wrappers at least 15584 bytes without a matching small upper bound. The code never infers a payload cap from these lower bounds.

The literal trace can repeat a recorded preimage at multiple positions. Its node count therefore cannot be bounded merely by the database's record count. A visited-record DAG might give a sharper representation, but would require a new theorem preserving least-preimage selection and missingness under record restriction. This lane preserves the literal trace and uses the source's logarithmic depth instead.

## Decision Log


Use unary length prefixes for byte strings and child counts. Their overhead is linear rather than logarithmic, but this makes the inverse elementary, preserves every byte, and keeps the requested register bound polynomial. Do not introduce an unexplained finite ordinal for raw inputs or assume an opaque injective codec. Decision: 2026-09-07.

Use the generic fuel-derived binary-tree budget. At the actual fuel 26 this is `2^27-1=16N-1` for `N=2^23`, so the literal tree remains linear in the source domain size. Do not call `2^fuel` polynomial in unconstrained fuel. The sharper stage-specific tree budget near `2N` is optional, not needed for polynomial register length. Decision: 2026-09-07.

Use `Fin capacity × Fin 8 → ZMod 2` as the answer register, with the already checked literal byte-to-eight-bits equivalence. This provides a finite additive group compatible with both scalar and counter-vector coherent instruments. It does not require importing the vector owner's uncached implementation. Decision: 2026-09-07.

## Outcomes & Retrospective


The 528-line source passed strict Lean checking and ten principal axiom audits. It establishes a prefix inverse for the complete trace forest, actual-source fitting and byte bounds, and injective embeddings into a fixed register with eight bits per bounded byte. The finite-key variant derives its byte-length bound from the actual finite key universe. The initial elaboration failures were repaired with explicit Option-bind reduction, multiplication monotonicity, matching raw-input equality instances, and explicit subtype projections; the byte grammar and resource statements did not change.

This completes the bounded-register representation milestone, not a polynomial reversible-runtime theorem, parser-runtime bound, source-extraction efficiency theorem, quantum gate count, or production authorization. The earlier one-hot implementation remains untouched. Scalar/vector endpoint integration and cached import artifacts are coordinator-owned and are not claimed by this module's isolated check.

## Context and Orientation


`SmallWoodV8Smz9CoherentMerkleGeometry.lean` defines the actual trace as `missing`, `budget`, or `record rawInput children`. `extract` selects the least valid recorded preimage at each source stage and recursively follows all ordered edges. `sourceNext` permits at most two edges and the DECS/PIOP source heights are 25/26. `SmallWoodV8Smz9CoherentMerkleInstrument.lean` maps finite database keys to literal raw byte inputs, defines `sourceLabel`, and currently supplies a faithful one-hot answer.

The new module's `Fits L fuel trace` guarantees that every recorded input has at most `L` bytes, every child list has at most two entries, and zero fuel contains only the explicit budget marker. This predicate is derived from the actual extraction and the actual key-byte bound; it is not a new source-correctness or successful-extraction assumption. Missing branches remain encoded.

## Plan of Work


The first milestone is an explicit byte grammar and prefix inverse. Zero and one are trace tags for missing and budget; two is the record tag. Each record then carries the unary length of its raw input, those exact raw bytes, the unary child count, and the ordered child encodings. The outer forest starts with its own count. The parser retains an unconsumed suffix, so decoding an encoded object followed by arbitrary padding recovers exactly the original object.

The second milestone derives fitting and size bounds from the actual source extractor. The selected-input-recorded theorem carries the input-byte bound down each record. A new list-arity lemma handles duplicated children correctly. The full binary budget satisfies `T(0)=1`, `T(f+1)=1+2T(f)`, hence `T(f)+1=2^(f+1)`. The explicit node and raw-payload counts of a fitting forest are at most `q*T(f)` and `q*L*T(f)`. A record needs at most `2L+5` local bytes, including unary input length and child count. A forest of at most `q` targets has byte bound

    C(L,f,q)=1+q*(1+(2L+5)*T(f)).

At fuel 26 this is

    1+q*(1+(2L+5)*(16*8388608-1)).

The third milestone pads the byte string to exactly `C` bytes and maps every byte to eight XOR bits. The prefix inverse ensures zero padding cannot merge distinct fitting forests. The resulting `BoundedForest` embedding and generic `rangeForestEmbedding` let either source-label endpoint supply a faithful fixed-length answer. `actualSourceLabelEmbedding` derives the needed facts for any finite database output type, so the vector owner can instantiate outputs as a counter-to-digest function without changing this module.

## Concrete Steps


Do not run Lean until the global coordinator grants a check slot. Once authorized, use one warm process from `formal/crypto`, with cached imports and no `-o` output:

    lake env lean -j1 -M3072 -DwarningAsError=true -DautoImplicit=false HegemonCrypto/SmallWoodV8Smz9SourceExtractionCodec.lean

Then audit the inverse, actual source fitting, byte budget, and label embedding declarations using the same warm toolchain with appended `#print axioms` commands on standard input. The coordinator alone owns caching and import integration. Source and documentation together must remain below the allocated 25 MiB; no domain materialization, database enumeration, or Rust build is part of this lane.

The executed audit streamed this same full source followed by `#print axioms` for each of the following declarations into `lake env lean -j1 -M3072 -DwarningAsError=true -DautoImplicit=false --stdin`. Both the standalone strict check and the audit exited zero. No `.olean` was written.

    HegemonCrypto.SmallWood.V8Smz9SourceExtractionCodec.decode_forest_encode
    HegemonCrypto.SmallWood.V8Smz9SourceExtractionCodec.encode_forest_injective
    HegemonCrypto.SmallWood.V8Smz9SourceExtractionCodec.source_extract_fits
    HegemonCrypto.SmallWood.V8Smz9SourceExtractionCodec.forest_node_payload_bounds
    HegemonCrypto.SmallWood.V8Smz9SourceExtractionCodec.source_forest_byte_bound
    HegemonCrypto.SmallWood.V8Smz9SourceExtractionCodec.logarithmic_fuel_node_budget
    HegemonCrypto.SmallWood.V8Smz9SourceExtractionCodec.bit_register_coordinate_count
    HegemonCrypto.SmallWood.V8Smz9SourceExtractionCodec.decode_register_encode
    HegemonCrypto.SmallWood.V8Smz9SourceExtractionCodec.actualSourceLabelEmbedding
    HegemonCrypto.SmallWood.V8Smz9SourceExtractionCodec.finiteKeySourceLabelEmbedding

Every listed declaration reported `[propext, Classical.choice, Quot.sound]`, except `logarithmic_fuel_node_budget`, which reported `[propext, Quot.sound]`.

## Validation and Acceptance


Strict Lean must succeed without warnings, `sorry`, `admit`, new axioms, or `native_decide`. The principal acceptance facts are `decode_forest_encode`, `source_extract_fits`, `source_forest_byte_bound`, `decode_register_encode`, and `actualSourceLabelEmbedding`. The answer dimension must depend on the explicit byte budget, not `Fintype.card` of the source-label range. The source namespace and exact trace type must remain unchanged. Axiom output must contain only the existing foundational axioms.

Security and efficiency claims remain separate: this proves representability and a faithful bounded register, not an efficient implementation of lexicographic database search, a quantum gate count, an efficient state preparation, or a polynomial-time reversible algorithm. The large full oracle table must not be enumerated to justify an efficiency claim.

## Idempotence and Recovery


The change is additive and owns only the new codec source/document plus the explicitly requested research note. Preserve all existing work and do not alter cached files or parent integration. Before any context checkpoint, keep unchecked status explicit. After a successful strict check, freeze the source hash and send it to the coordinator for cache output.

## Artifacts and Notes


Vector owner endpoint: `V8Smz9CoherentVectorMerkle.coherent_faithful_vector_source_commutator_bound`, consuming `VectorLabelRange ... ↪ Answer`. Scalar endpoint: `V8Smz9CoherentMerklePartition.coherent_faithful_source_commutator_bound`, consuming `SourceLabelRange ... ↪ Answer`. Both require a finite additive answer group. No endpoint integration is claimed by this isolated check.

Frozen source: 528 lines, 25,568 bytes, SHA-256 `f22ceace36394508792f73ca726c90de19be21e7d5160448fce71eadc88998c2`. Principal anchors are forest inverse line 162, actual-source fitting line 343, actual-source byte bound line 373, register inverse line 430, explicit-byte-bound source-label embedding line 503, and finite-key-bound embedding line 517. The worker created no shared cache, runtime output, or domain-sized enumeration.

## Interfaces and Dependencies


The new namespace is `HegemonCrypto.SmallWood.V8Smz9SourceExtractionCodec`. The general output type is `BitRegister capacity`, with exactly `8*capacity` bit positions. `actualSourceLabelEmbedding keyBytes outputBytes L fuel q targets keyBound targetBound` embeds the literal range of `sourceLabel` into `BitRegister (forestByteBudget L fuel q)`. Its `keyBound` is the actual statement `forall key, (keyBytes key).length<=L`, and its target bound is `forall target, (targets target).length<=q`. No query-record cardinality is substituted for the raw-input byte bound.

`keyByteBudget keyBytes` is the finite supremum of actual key byte lengths, and `key_bytes_le_budget` derives its bound. `finiteKeySourceLabelEmbedding` can therefore obtain the resource bound from the finite key universe without assuming an opaque finite-label codec. This supremum is a mathematical resource parameter; the module does not claim that enumerating the key universe to compute it is efficient. `logarithmic_fuel_node_budget` states the general identity `T(domainLog+3)+1=16*2^domainLog`, making the polynomial-in-domain-size dependence explicit rather than merely treating fuel 26 as a hidden constant.

Revision: strict elaboration repairs, ten principal axiom audits, frozen hash, and explicit representation-versus-runtime boundary recorded on 2026-09-07.
