# Concrete coherent Merkle substitution for SMZ9

2026-09-07. Research/instantiation note, not a completed Lean theorem or a
production security certificate. No builds or runtime changes were made in
this lane.

## Result

The Merkle part has a concrete route with explicit constants. Use a
deterministic extractor for the **framed commitment graph**, not just the bare
binary tree. Its outgoing digest arity is at most two, including SMZ9's hash
wrappers. A fresh database insertion can change extraction only by hitting a
selected target or an already recorded child digest. Consequently, the
classical partition instability is at most `3t / 2^512`; the coherent
commutator squared norm is at most `240(t+1) / 2^512`.

This closes the conceptual choice of quantum technique. It does not yet close
the implementation refinement, actual round-by-round decoder bound, or the
hash-chain/counter-block compilation. Those are concrete residual conditions
listed below, not assumed probabilities.

## Primary source and inspection record

Alessandro Chiesa, Zijing Di, Zihan Hu, Yuxi Zheng,
[*How to Prove Post-Quantum Security for Succinct Non-Interactive Reductions*](https://eprint.iacr.org/2025/2166.pdf),
March 2, 2026 revision, 102 pages; SHA-256
`2cfb88c76732d9f39f4b1943b4aabc0390dd3d17830d91d910c38e16e4bb5a30`.
The full official PDF was downloaded and read, not reconstructed from search
snippets. Relevant complete material inspected: Definitions 3.5-3.6; Section
5 and its commutator proof; Theorem 6.10 and proof, with Lemmas 6.6-6.8;
Definitions 7.1-7.3; Sections 8-9, including the complete proof of Theorem 8.4;
Theorem 11.3, Constructions 11.7-11.9 and the complete Lemma 11.6 hybrid proof;
Appendix A. Formula layouts on pages 53, 54 and 79 were visually checked.

The source is distributed under CC BY according to its
[official record](https://eprint.iacr.org/2025/2166).

## Constants, with their correct metrics

Write `t` for the query bound in the stated experiment, `wVC` for total quantum
query mass to commitment-oracle channels, `q1` for the total opening-check
query bound, `q2` for a full-domain opening-check query bound, and `n` for the
number of extracted commitments checked. These are not interchangeable with
the protocol's lifetime `Q`, honest proof views `T`, or target count `V`.

Theorem 5.4 gives `||[U_E,O^(t)]||^2 <= 80 I(P,t)` for a computational-basis
database partition and unitary conditioned on its cells. Theorem 8.4 and the
Merkle instability calculation then give:

| Quantity | Bound at output width 512 | Meaning |
| --- | --- | --- |
| `kappa_sim` | `0` | Exact compressed-oracle simulation. |
| `kappa_com` | `240(t+1)/2^512` | Squared Euclidean distance between the two query orders. |
| `kappa_extract` | `8 n q2/2^512` | Failure of the extracted partial object's own opening check. |
| `kappa_offline` | `(160 wVC t^2 + 16 q1)/2^512` | Accepted openings inconsistent with offline extraction. |
| `kappa_online` | `240 wVC t^2/2^512` | Squared difference of square roots of success probabilities in the two recording experiments. |

Do **not** read `kappa_online` as a trace-distance bound of that same size, or
take its square root and then add it as an ordinary failure probability.
The composition proof handles its metric explicitly, yielding factors 4 and
8 below. Unitary queries to the extractor itself are allowed in these games.

## Exact source geometry and the hidden wrapper hashes

The relevant backend is `Sha512Poseidon2V8Smz9`, profile 6, not HX512 or a
truncated compact backend. It uses the complete 64-byte digest
([backend](../../../circuits/transaction/src/smallwood_engine.rs#L514)).
The raw preimage is

```text
LE64(profile-domain length) || profile-domain
|| LE64(role-domain length) || role-domain
|| LE64(word count) || LE64(word[0]) || ... || LE64(word[last])
|| LE64(counter)
```

See [raw SHA-512 function](../../../circuits/transaction/src/smallwood_engine.rs#L4237).
The profile domain is
`hegemon.smallwood.poseidon2-v8.smz9.sha512.profile.v1`.

| Framed role | Payload | Digest children followed by extraction |
| --- | --- | --- |
| Strict-ZK Merkle leaf | Global 32-byte salt; leaf index; 64-byte leaf tape; count 140; 140 data fields; count 5; five mask fields | None |
| Merkle node | Left 64-byte digest, right 64-byte digest | Two |
| Merkle root binding | Global salt, bare root, statement-binding words | One bare-root digest |
| PIOP input | Root-binding digest, five reconstructed DECS response polynomials, statement-binding words | One root-binding digest |

Leaf fields occupy 160 words / 1,280 bytes before outer framing. The 145
Goldilocks values contribute 9,280 encoded bits. The per-leaf salt corresponding
to the paper's `nu` is the **512-bit tape**, not the global 256-bit salt. Treat
the latter, the position and counts as message/context fields; the raw leaf
encoding is not bare `H(tape || row)`.
[Leaf layout](../../../circuits/transaction/src/smallwood_engine.rs#L11608).

SMZ9 internal nodes do not include depth or index: those arguments affect
HX512 only. Their role is `hegemon.smallwood.level5.merkle-node`.
[Node function](../../../circuits/transaction/src/smallwood_engine.rs#L12990).

Most importantly, the matrix-query input is **not** the bare root:

```text
DECS coefficients: H_decs(hash_mt, counter)
  hash_mt = H_root(salt, bare_root, binding)

PIOP batching: H_gamma(hash_fpp, counter)
  hash_fpp = H_piop_input(hash_mt, DECS_responses, binding)
```

Thus extraction needs one wrapper before the DECS matrix, and two before
PIOP batching. See [root binding](../../../circuits/transaction/src/smallwood_engine.rs#L11825),
[response transcript](../../../circuits/transaction/src/smallwood_engine.rs#L11499),
[matrix sampling](../../../circuits/transaction/src/smallwood_engine.rs#L11915),
[batching sampling](../../../circuits/transaction/src/smallwood_engine.rs#L11946).
The two-wrapper result includes the recorded DECS responses; it must not
replace them with polynomials chosen after PIOP gamma is known.

## Framed graph extractor and stability proof

Fix a finite raw-byte query domain large enough for the bounded adversary and
source verifier. Let `D` be a finite partial map from these exact byte strings
to 512-bit outputs. Define `E_phase(D,c)` as follows:

1. Starting at target `c`, select the lexicographically first recorded preimage
   of the required role and canonical shape. A missing or malformed required
   preimage produces a typed missing value.
2. Follow the root-binding wrapper, and also the PIOP-input wrapper when the
   phase requires it. Retain their complete selected payloads, not just digest
   children. Check the externally pinned context/shape when converting them
   into a source object.
3. Traverse the binary tree to depth 23. At each position, select the required
   node or leaf preimage, check the global salt, leaf index, tape width, counts
   and canonical field encoding, and retain valid rows plus their tapes and
   authentication data. Unrecovered leaves remain `bottom`.
4. Produce a deterministic partial table and trapdoor. A later fixed
   zero-completion for the algebraic decoder is a separate deterministic map;
   do not claim that the missing leaves were recovered.

Do not abort extraction merely because an *unrelated* database collision
exists. Collision-freedom is a separate bad-event partition for opening
consistency. Global collision rejection would destroy the local stability
argument below.

Define `Children(D)` by parsing the designated digest-child fields above,
over all recorded inputs. Each input contributes at most two children, so
`|Children(D)| <= 2|D|`. It is not the set of arbitrary 512-bit substrings of
all query inputs.

**Fresh-insertion lemma.** If `x` is absent from `D` and

```text
E_phase(D,c) != E_phase(D + [x -> y], c),
```

then `y` is in `{c} union Children(D)`.

Proof: follow the two deterministic executions to their first differing
preimage selection. The only added record is `x -> y`; therefore its output
equals the digest sought at that step. At the first step that digest is `c`.
Otherwise the parent selection has not yet differed and comes from `D`, so
the sought digest is one of its parsed children. The same argument covers a
formerly missing path and a new lexicographically earlier preimage. Depth and
the number of already selected nodes do not multiply this set size.

For a fixed list of `j` targets, partition databases by the entire tuple of
extraction outputs. For a fresh uniformly sampled 512-bit `y`, leaving the
current partition cell has probability at most

```text
(j + 2|D|) / 2^512 <= 3t / 2^512      when j <= t and |D| < t.
```

The separate collision partition has instability at most `t/2^512`: a new
output collides with at most `|D|` existing outputs, and adding a record cannot
erase a collision. These are classical counting statements for **arbitrary**
databases, not an ideal-source sampling assumption.

Lift the deterministic procedure reversibly:

```text
U_E |phase,c,D,z> = |phase,c,D,z XOR E_phase(D,c)>.
```

This is a unitary permutation of a finite computational basis. The partition
argument and Theorem 5.4 then give the commutator bound above, including
superposed targets and an entangled residual adversary register. The online
comparison uses the paper's `Record`/`Split` construction, not a premature
measurement of `D` or a copied classical candidate.

## Checking constants for actual SMZ9 openings

The source recomputes 20 leaf hashes and 23 levels for all 20 lanes. Its
`BTreeMap` shares sibling information but does not deduplicate propagated
lanes. Therefore a fully processed proof uses **480** raw tree-hash calls,
then one root-binding call; checking the PIOP-input wrapper adds one more.
[Verifier loop](../../../circuits/transaction/src/smallwood_engine.rs#L11292).

Use the generic Theorem 8.4 with `q1=482` for the two-wrapper graph. A
conservative full-domain checker that follows the same per-lane method has
`q2=24N+2`, where `N=2^23`. Hence

```text
kappa_extract <= 8n(24*2^23 + 2)/2^512
kappa_offline <= (160 wVC t^2 + 7712)/2^512.
```

These counts deliberately include leaf hashing. The paper's simplified
Theorem 8.3 uses `q1=qs log(ell)` and `q2=ell`; its own displayed leaf-hashing
construction does not justify copying those counts literally for this Rust
checker. A memoized checker could lower the full-tree count, but needs its own
equivalence proof. The proof's compact authentication-node count is not the
verifier's raw hash-call count.

## Raw counter blocks: a concrete conservative compiler

For one valid role/prefix and a fixed source cap `L`, group the random blocks
into a vector-valued random function

```text
F(prefix) = (H(frame(prefix,0)), ..., H(frame(prefix,L-1))).
```

Disjoint, injectively framed inputs make this an exact regrouping of one
random function, not a new cryptographic assumption. Other roles, malformed
inputs, and counters outside the cap stay as independent complement channels
of that same raw oracle.

A coherent query for one selected block can be simulated with **two** full
`F` queries: compute the vector into fresh workspace, XOR the selected block
into the answer, then uncompute the vector. The prefix and counter may both
be in superposition. Thus a conservative compilation costs `t <= 2Q` before
the explicitly added verifier/reduction calls. Count the full vector's
workspace and gate cost; do not pretend each raw block yields a whole matrix.

For current coefficient sampling, the source cap is
`ceil((requested_words + 32)/8)`. The DECS matrix uses 700 field words, so
`L=92`. PIOP batching uses `5 * max(830, retainedLinearRows)`, not merely the
830 nonlinear roots. The active program's 15,561 nonempty raw-replication
rows already give a lower bound; all CSR attempts number 20,605. Under those
retained-count bounds, gamma uses 77,805–103,025 words and a cap of
9,730–12,883 blocks. Its exact count depends on the public statement.
DECS has 47,104 raw bits; a common maximum-width compiler has 6,584,320 raw
bits per vector answer. The generic two-query simulation is unchanged, but
its workspace/gate accounting must include this corrected width.
[Cap](../../../circuits/transaction/src/smallwood_engine.rs#L1999),
[sampling loop](../../../circuits/transaction/src/smallwood_engine.rs#L4299).
The maximum-count rule is
[derive_gamma_prime](../../../circuits/transaction/src/smallwood_engine.rs#L11929);
the retained count comes from
[the actual adapter](../../../circuits/transaction/src/smallwood_poseidon2_v8_semantics.rs#L4100).

The interactive verifier in this compilation must run the **actual**
canonical-field rejection sampler on those bits, including its failure
behavior. Accepted values of a fixed-length rejection sample are uniform
conditional on obtaining enough values, because the acceptance predicate
depends only on membership in the field range, not which accepted value was
drawn. This symmetry can justify carrying an ideal-field bound to that one
round only after the protocol rejects exhaustion. It does not establish the
other rounds' admissible-point or distinct-subset laws.

Apply coherent extraction to the prefix before the grouped challenge is
answered, and uncompute afterward. Retain source, wrapper responses and raw
commitment/trapdoor information in the state-restoration query encoding. In
particular, grouping cannot silently erase previously queried counter blocks
or changes in extracted prefixes: their handling is part of the required
`Record`/`Split` simulation and hash-chain prefix refinement.

## Explicit composition and numerical consequence

For a genuine relaxed round-by-round knowledge extractor with worst-round
error `mu`, Theorem 6.10 gives

```text
kappa_sr <= 80(t+k+1)(wFS+k)*mu + (t+k+1)k/2^rmin.
```

Its hypotheses quantify over **every** pre-verifier transcript and an
existential next knowledge witness inside the bad-event probability. A
decoder proven only against one fixed response or one final query set does
not satisfy this definition.

Theorem 11.3 gives the following ledger; each term retains its own prescribed
query arguments rather than reusing a per-proof `Q`:

```text
kappa_KS <= 4 kappa_sr
          + 4 kappa_extract(2t+1, ...)
          + 8 kappa_offline(2t+1, ...)
          + 4 kappa_online(t+1+qV+k+qCR+qCR', ...)
          + 2 qV^2 kappa_com(t+1+k+qV, ...).
```

Here `qV` is the entire verifier's raw-oracle query complexity, not 482;
`qCR,qCR'` count the relation deciders. For no implicit input commitments,
the `kappa_extract` contribution is zero. Retain the opening-consistency
`kappa_offline` contribution even with no output implicit commitments:
Appendix A explicitly retains it. The suggestion to drop it in Remark 11.5
should not override the complete hybrid proof.

The leading round-by-round loss is therefore `320 t^2 mu`, not `6Q^2 mu`.
The following are **leading-term calculations only**, at `Q=2^64` and
`p=18446744069414584321`; they are not endpoint certificates:

| Candidate bound for `mu`, omitting its small-query tail | `t=Q`, `B=2^52` | Conservative `t=2Q`, `B=2^52` |
| --- | --- | --- |
| Original `140B/p^5` | Approximately `2^-124.549` | Approximately `2^-122.549` |
| Proposed factor-free `(p/(p-1))B/p^5` | Approximately `2^-131.678` | Approximately `2^-129.678` |

For the factor-free bound, the leading-term-only thresholds are
`log2(B) < 55.678` and `<53.678`, respectively. The factor-free geometric
reduction was being developed independently during this assessment; its
universal applicability and numerical `B` bound must both be proved. The
full budget must also include all other rounds, tails, target composition and
refinement errors.

An exact integer cross-multiplication check, including
`w415 = choose(415,20)/choose(2^23,20)`, gives, for `t=2*2^64`, `k=4`, and
`B=2^52`,

```text
320(t+5)(t+4) * (w415 + (p/(p-1))*B/p^5) < 2^-129,
```

but not `<2^-130`. Its logarithm is approximately `-129.678068589`.
This checks the arithmetic conditional on the factor-free recovery theorem;
it does not prove that theorem or identify the actual compiled round count.

## Remaining conditions and finite resources

1. **Framed graph refinement:** implement the selected-preimage extractor and
   prove its parser, wrapper and compact-opening equivalence to SMZ9 bytes.
   The first-divergence proof above supplies the exact classical lemma for
   the separate `CoherentMerkleGeometry` lane.
2. **Physical coherent instantiation:** instantiate the paper's operators,
   sparse database representation, and valid measurements in the chosen
   physical Lean QROM model. A norm-preserving arbitrary function is not enough.
3. **Hash-chain/BCS interface:** show that extraction of the latest wrapper
   supplies the complete ordered interactive prefix consistently. The paper's
   Construction 11.7 contains explicit commitment tuples with distinct oracle
   indices; SMZ9's digest-only, shared-oracle inputs are not literally that
   syntax. Do not claim Theorem 11.3 applies before this refinement.
4. **Counter compiler and samplers:** prove the two-query grouping simulation
   for every used role, exact cap and retry policy, and verify mandatory
   rejection on exhaustion. Establish the actual raw-bit round-by-round game.
5. **Knowledge extractor:** discharge the response decoder's universal
   round-by-round bound, fixed-program PIOP implications and semantic witness
   decoding. No extractor-success premise replaces these proofs.
6. **Lifetime accounting:** supply global `Q`, explicit verifier/reduction
   overheads, and the `V`-target joint experiment. Repeated targets share the
   same database; do not reset it or identify `V` with honest-view count `T`.

The deterministic tree/wrapper procedure has at most `2N+1` selected graph
vertices in the two-wrapper case. Naive sparse lookup costs
`O((2N+1)t Lmax)` elementary bit operations, where `Lmax` bounds a recorded
input length; output and reversible workspace are additional. The field table
alone is 9.0625 GiB; storing all leaf tapes and full tree labels adds about
1.5 GiB before interpreter overhead. This is polynomial-time in the stated
parameters, not a practical laptop extraction measurement. The coefficient
counter-vector workspace is at most 267,776 bits for the two matrix stages.

This lane used about 2.4 MiB of temporary paper/text/page-render files and one
small Markdown note. No full source table or proof artifact was materialized.
