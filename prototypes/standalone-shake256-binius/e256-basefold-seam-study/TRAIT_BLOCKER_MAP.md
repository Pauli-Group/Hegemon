# B128-commitment / E256-BaseFold seam: exact blocker map

This is a source-only implementation study against pinned Binius revision
`3f96163049f680b2909f6545690bd929f1b48c44`. It deliberately contains no
patch: the desired mixed-field path is not a coherent small adapter over the
pinned prover APIs. No Cargo build, prover run, security claim, zero-knowledge
claim, or frontier mutation is associated with this map.

## Required type split

The requested path has two different scalar roles:

```text
K = BinaryField128bGhash             committed symbols, NTT twiddles
L = GhashSq256b                      challenges, claims, transparents, folds
[L:K] = 2
```

`GhashSq256b` is a real field, not `K x K`. Pinned
`crates/field/src/ghash_sq.rs:3-12,51,72-78,93-109` fixes the extension,
basis, and 32-byte encoding. The desired commitment must bind ordered K
coefficient lanes while every algebraic fold is one operation in L.

There are two distinct implementation routes, and only one preserves the
requested 16-byte committed-symbol type:

1. **Stock-field route:** instantiate all BaseFold types with `F=L`. This is
   algebraically coherent because L implements `BinaryField`, but the Merkle
   channel commits and opens 32-byte L elements. It does not commit K symbols.
2. **Mixed route:** commit K symbols, lift authenticated openings into L, and
   keep all challenges, claims, sumcheck messages, and post-first-fold
   codewords in L. This is the requested route. Neither top-level channel can
   currently express it.

Calling the stock-field route a B128-symbol commitment merely because the
32-byte L serialization contains two B128 coefficients would erase the type
and wire distinction. It would not save opening bytes and is rejected here.

## What is already coherent

### Field and tensor algebra

- `crates/field/src/ghash_sq.rs:51,72-78` implements the genuine degree-two
  field `L/K`.
- `crates/math/src/tensor_algebra.rs:24-50,95-109` is generic over `(K,L)` and
  can represent `TensorAlgebra<BinaryField128bGhash,GhashSq256b>`.
- `crates/iop/src/fri/fold.rs:16-27,56-93` already implements the arithmetic
  kernel `fold_chunk<L,K,NTT>`, with K-valued NTT twiddles and L-valued pairs,
  challenges, and results.

### Apparent verifier split is not a field split

`IPVerifierChannel<K>` has an associated `Elem`, but requires
`Elem: FieldOps<Scalar=K>` at `crates/ip/src/channel.rs:41-43`. A concrete field
implements `FieldOps` with itself as `Scalar` at
`crates/field/src/field.rs:136-138`; therefore concrete L has `Scalar=L`, not
K. `IPVerifierChannel<K, Elem=L>` is ill-typed.

The same constraint propagates through:

- `BaseFoldVerifierChannel<K,Channel>` at
  `crates/iop/src/basefold/channel.rs:50-70,144-254,317-355`;
- `FRIQueryVerifier<K,Elem,Commitment>` at
  `crates/iop/src/fri/verify.rs:29-48,77-181,189-268`;
- the transcript Merkle channel, which sets `Elem=F` and reads openings as the
  same F at `crates/iop/src/merkle_channel.rs:108-145,201-245`.

The associated `Elem` supports symbolic or packed operations over scalar K;
it is not an extension-field hook. Both verifier and prover channel traits
must split K from L.

## Hard integration blockers

### 1. The IP channels cannot separate observed and algebra fields

`IPProverChannel<F>` sends, observes, and samples the same F at
`crates/ip-prover/src/channel.rs:35-81`. With `F=K`, it cannot sample L. With
`F=L`, it no longer exposes a K observation/commitment boundary. This is the
first trait-level blocker. The verifier's `FieldOps<Scalar=F>` restriction
above is the matching blocker on the other side.

The minimum symmetric API needs separate types, conceptually:

```text
MixedIPProverChannel<K,L> / MixedIPVerifierChannel<K,L>
  send/receive/sample/assert: L
  observe:                    K -> transcript state, returned as L
```

Changing only the transcript adapter is insufficient because every caller is
currently generic over the single `F`.

The word channel is another geometry constraint, not a cosmetic generic. Its
`n_packed_elems` and `pack_words_concrete` derive the number of 64-bit words
per committed element from `F::N_BITS` at
`crates/ip/src/channel.rs:183-210`. Substituting `F=L` packs four words per
element instead of B128's two. A mixed profile must retain K for statement and
trace packing, then lift K values into L for algebra; an all-L type swap changes
the committed relation layout.

### 2. The oracle prover channel couples message and transparent fields

`IOPProverChannel<P,A>` commits `FieldSlice<P>`, queues
`FieldVec<P,A>`, and takes a `P::Scalar` claim at
`crates/iop-prover/src/channel/mod.rs:27-73`. The mixed path instead needs:

```text
message/finalize: K-packed buffer
transparent:      L-packed buffer
claim:            L
```

This requires two packed types (`PK::Scalar=K`, `PL::Scalar=L`) or a dedicated
mixed relation object. A wrapper cannot implement the existing trait without
either narrowing L values to K or widening the committed oracle to L.

### 3. BaseFold prover storage and Phase A use one field

`BaseFoldProverChannel` fixes `P::Scalar=F`, `NTT::Field=F`,
`FRIParams<F>`, and `MerkleIPProverChannel<F>` at
`crates/iop-prover/src/basefold/channel.rs:88-110`. Its committed messages,
masks, transparents, claims, batching challenges, and combined witness all
remain the same field at `:197-210,248-393`.

In the mixed path, the initial message/mask/codeword are K, while sampling an
L masking or batching challenge immediately makes the blinded message,
sumcheck state, and combined witness L. Phase A therefore needs a real
mixed-field sumcheck or an explicit K-to-L lift before proving. Replacing a
type alias cannot express that transition.

### 4. The FRI prover first fold changes scalar type

`FRIFoldProver` requires `P::Scalar=F`, `NTT::Field=F`, stores
`FRIParams<F>`, and returns F codewords at
`crates/iop-prover/src/fri/fold.rs:24-60,87-145,208-301,318-342`.

The desired state machine is heterogeneous:

```text
initial committed codeword: K
first L-challenge fold:      K -> L
all later codewords/folds:   L
NTT twiddles throughout:     K, lifted into L
```

The low-level verifier fold kernel already supports this, but the prover
folder, first-fold batch folder, later-fold oracle vector, and terminal
codeword types do not.

### 5. Merkle prover commitments and openings use one scalar type

`MerkleIPProverChannel<F>` accepts only packed buffers with `Scalar=F` at
`crates/iop-prover/src/merkle_channel.rs:33-76`; the transcript implementation
uses the same F for messages, roots, leaf serialization, and openings at
`:134-229`.

A mixed channel needs at least two authenticated layouts:

```text
initial tree: K leaves
later trees:  L values encoded as exactly two ordered K coefficient lanes
```

The commitment handle must carry the layout so the verifier knows whether one
or two K symbols reconstruct each returned L element. Always transmitting two
lanes would be coherent but would charge 32 bytes for every initial opening
too, defeating the B128-symbol objective. No current method communicates that
layout.

`FRIQueryProver` repeats the same coupling: the original and later query
oracles all require one `MerkleIPProverChannel<F>` at
`crates/iop-prover/src/fri/query.rs:14-23,60-80,126-170,174-242`.

The proof-size optimizer also assumes one uniform serialized field width.
`crates/iop/src/fri/size_estimation.rs:16-50` and the parameter search in
`crates/iop/src/fri/common.rs:535-570,620-623` price every tree through one F.
The mixed route has 16-byte K values in the input tree and 32-byte L values
(two K lanes) after the first fold. Choosing K underprices later rounds;
choosing L overprices or widens the initial tree. Parameter selection must be
layout-aware before any byte comparison is meaningful.

### 6. Pinned ring switch is B1 -> B128, not B128 -> E256

The prover fixes B1, B128, 128 rows, seven packing variables, B128 evaluation
points, and `IPProverChannel<B128>` at
`crates/prover/src/ring_switch.rs:24-26,48-53,102-175,260-336`.
The verifier similarly derives packing from the absolute degree of its `F`
and constructs `TensorAlgebra<B1,_>` at
`crates/verifier/src/ring_switch.rs:48-76,104-123`.

For DP24's degree-two `K -> L` ring switch, the base tensor algebra must be K,
packing consumes one K-variable, and the clear tensor-algebra message contains
two L elements. Merely running the existing B1 -> B128 ring switch with an L
verifier `Elem` widens challenges, but it is not the DP24 B128 -> E256 packing
map described by `diamond-ring-switch-map`.

### 7. Two branches cannot be added by cloning one compiler channel

The existing E256 transport KAT correctly forks two states after the shared
context/root and labels them `stream-a` and `stream-b` at
`strict-e256x2-iop/src/lib.rs:612-681`. Stock BaseFold has one linear
transcript/channel, one FRI state machine, and one owned prover commitment
handle. It has no branch label, transcript fork, or shared immutable
commitment registry.

The minimum two-branch orchestrator must:

1. commit the immutable K table before either branch samples a coin;
2. absorb the same root plus distinct fixed branch labels;
3. keep every challenge-dependent message, root, query list, abort, and
   terminal claim branch-local;
4. open the union of two independently sampled query lists against the one
   immutable commitment without reusing either query schedule.

Sharing a root alone does not authorize sharing challenges or query indices.

The KAT is an arithmetic/transport oracle, not a drop-in PCS layer:

- `E256CoefficientLanes::from_b128_table` at
  `strict-e256x2-iop/src/lib.rs:396-402` zero-lifts every K value to `(v,0)`;
  it does not pair two adjacent K coefficients into one L value or remove one
  variable as DP24 requires.
- Its query schedule depends on `(context, root, label, draw)`, not a complete
  BaseFold branch history.
- Its explicit E256 terminal claims are serialized but the Merkle verifier
  authenticates only B128 paths; the KAT manifest correctly leaves PCS binding
  and proximity false.

### 8. The active M4 wrapper fixes B128 end to end

The current M4 verifier requires `IOPVerifierChannel<B128>` with
`Channel::Elem: FieldOps<Scalar=B128>` and owns a
`BaseFoldVerifierCompiler<B128>` at
`crates/m4-verifier/src/composite.rs:130-162,194-220`. The prover likewise
requires `P::Scalar=B128`, `WordIPProverChannel<B128>`, and a B128 BaseFold
compiler at `crates/m4-prover/src/composite.rs:96-105,128-136`; its NTT is
concretely B128 at `crates/m4-prover/src/prove.rs:55-56`.

Consequently the mixed seam cannot be attached below the M4 wrapper without
also preserving B128 word/trace geometry while changing every algebraic
channel result to L. An isolated Merkle adapter would not reach the reduction,
ring-switch, or claim types.

## Diamond artifact boundary

The existing `diamond-ring-switch-map` has a coherent paper route, but its
exact interface says `pack_K_to_L` followed by `commit_L`; see
`README.md:105-131`. Its full wire model charges 32-byte E256 values. It does
not supply a B128-symbol vector PCS.

Preserving one original B128 root while authenticating L-linear projections
needs a new binding vector/coefficient-lane PCS (or an equivalent adjoint
opening argument). This is the same substantive boundary as the mixed prover
traits above, not a serializer-only change.

## Smallest coherent implementation boundary

No isolated one- or two-file patch is type/API coherent. The smallest honest
implementation unit is a new mixed BaseFold module, leaving stock BaseFold
unchanged, with all of these pieces landing together:

1. Paired `MixedIPProverChannel<K,L>` / `MixedIPVerifierChannel<K,L>` traits
   and matching transcript implementations.
2. Paired mixed IOP traits using K oracle buffers and L
   transparents/challenges/claims.
3. Layout-tagged mixed Merkle prover/verifier channels that authenticate K
   symbols and reconstruct L exactly from two ordered lanes.
4. A mixed Phase-A sumcheck over K messages and L transparents.
5. A heterogeneous FRI prover whose first fold is K-to-L and later folds are L,
   using K NTT twiddles.
6. Matching FRI commitment scheduling and layout-aware proof-size selection.
7. A generic degree-two `K -> L` ring switch, not the pinned B1-specialized
   one.
8. A two-branch orchestrator with fixed pre-coin commitment and explicit
   domain separation.
9. Differential tests against the existing `strict-e256x2-iop` arithmetic and
   branch transcript KATs, plus exact parser/round-trip tests for both Merkle
   layouts.

The public `ExtensionField::{from_bases,iter_bases}` API is sufficient for
canonical K/L conversion; pinned `GhashSq256b::{to_coeffs,from_coeffs}` is
private. Every tensor-algebra message parser must enforce exactly two L
elements before construction because `TensorAlgebra::new` pads or truncates
at `crates/math/src/tensor_algebra.rs:34-45`.

Until those pieces compile and cross-check together, a patch containing only
traits or a verifier adapter would create a misleading half-interface. This
study therefore emits the blocker map and no patch/checker.

## Source pins

All pinned-source paths below are relative to
`/private/tmp/binius64-api-3f961630` at the revision named above.

```text
746b8df934cd665a93ff53c09dbabe867a05581f717179b5a2fa4e0366d06182  crates/field/src/ghash_sq.rs
14d008d79defaafb9bfac7393bea8a2fe27aeb28a368cfa8f08e3f436e573324  crates/field/src/field.rs
e546abe8655e92c6730f1f4adc032df6f8e3673b5f55a9f9de813b1a28cb6300  crates/field/src/extension.rs
303193876ef9170e45b2c030da659ff733bce19e3e2ad06639459b6e87205761  crates/math/src/tensor_algebra.rs
62236feaefac28ddb191190de694ef9efb9887beb53a0105f7015556f18af850  crates/ip/src/channel.rs
4c236069a14b93b71be9ff1640a327151016a4a3a038bdec22f830b46ec44cd0  crates/ip-prover/src/channel.rs
03d7f000144c0839e045ce1eb0a1c8d7659bb111b3bf26d2d4647f77db1e6164  crates/iop/src/merkle_channel.rs
aea4681ca9538622cb25d2fc936eb2a38abb01283a525e52f48ec5d293193bac  crates/iop-prover/src/merkle_channel.rs
fbad7eacb1256a8b90659c6e6103556e0f6e0149b888e25ec4741a15ad71c6a7  crates/iop/src/basefold/channel.rs
7f1f5204619e0b3ceb7ddbb49a9f463b0bc56248bc59070d1f189f19d04820b0  crates/iop-prover/src/basefold/channel.rs
3f7039e7a9382b50c46aa859822162162e21ee6d3a0660e2c609b1e118548512  crates/iop/src/fri/fold.rs
2131676d78f0b56b4cb96a80199c8cc35339c71666bb26a5a0dcd5acf56c2420  crates/iop/src/fri/common.rs
d0998c7111d7cb8ab16f0a417c57bf60c5bb5ff25c28389cead4789e70e7d748  crates/iop/src/fri/size_estimation.rs
e87ba42195e4450d5d7c91626e1f7cfc11272f52722bb71946e6141162f3aa67  crates/iop-prover/src/fri/fold.rs
c5c8f55dd71944943162fd4c4bbbcb9d60e83df9da679ded650cbc131ccd9630  crates/iop-prover/src/fri/query.rs
166d0eaa1d8991eebcb6efc3254874637084c9a3f2deb4ce8b2b722e5c240eed  crates/iop/src/fri/verify.rs
b693c40c027a7b66aef4f97d7fb2168544c3cdfa1188af6681acd8bada97fbad  crates/prover/src/ring_switch.rs
8554ed97cab8f4d3c0c9cfde5152b92ebc983c010b6dd7152f5bc22491f7c973  crates/verifier/src/ring_switch.rs
d8bcd73dd7c8f8afa829a2de29d4826f1043afdab6121a217597712585f473c0  crates/m4-verifier/src/composite.rs
d2ac41db2809f2c394c239c0de24fddf89d808775842a7333d00918261d08e77  crates/m4-prover/src/composite.rs
b04cc2d07e9aca02361d8cf2cca3f1275f00d9a71ba0f00ea5fe5f0973bcf7bd  crates/m4-prover/src/prove.rs
```

Local artifact pins used for the comparison:

```text
7c7b4328d934d01cbe5b243291863237544c561b31f3306d3ac98e7867513693  strict-e256x2-iop/src/lib.rs
6865d7f8ff46c80462b12a20ad33ef3ca1e03ab9bd2f17dfa551861c7f070cd9  diamond-ring-switch-map/wire_terms.py
```
