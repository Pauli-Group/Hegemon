# Classical SMZ9 Merkle-extraction instability geometry

## Result and boundary

`SmallWoodV8Smz9CoherentMerkleGeometry.lean` implements a deterministic extractor
on finite recorded raw-oracle maps and proves

`Pr_y[extraction changes after inserting (x,y)] <= (j + 2 |D|) / 2^512`.

Here `y` is one uniformly sampled **raw 64-byte output**, `D` is the old
database, and `j` is the number of tracked prefix targets. Consequently, for
`|D| < t` and `j <= t`, the bound is `3t / 2^512`. This holds with one root
wrapper before the DECS challenge and with both the PIOP-input and root wrappers
before PIOP batching gamma. There is no extra factor for depth 23 or for the
number of unopened leaves.

This is the classical insertion/partition-instability component. It is not a
physical compressed-oracle commutator theorem, a quantum extraction instrument,
an accepted-opening consistency theorem, or a complete SMZ9 knowledge-soundness
argument. The companion [substitution assessment](coherent-merkle-substitution.md)
describes the remaining lifting conditions.

## Concrete finite-map algorithm

The database representation is a finite set of `(raw input, raw output)`
records. `Functional` checks that it is single-valued; `Fresh` checks that a
new key is absent. `insert_functional` proves that a fresh insertion preserves
the queried-map property. The stability theorem is stronger: it works on every
finite recorded relation, so it does not need a collision-free premise.

For each requested `(stage, digest)`, `selectedInput` filters the database to
preimages with that output whose parsed role is valid for the stage, then
selects the lexicographically least raw preimage. `extract` follows its parsed
outgoing digest fields recursively. A missing or invalid path gives an explicit
missing trace, not a postselected successful result. Complete selected raw
preimages are retained in the output trace, including wrapper response and
binding payloads. An unrelated database collision never invalidates the whole
extraction.

The stage rules are explicit:

| Starting stage | Next stages | Root-to-leaf records |
| --- | --- | ---: |
| DECS / `hash_mt` | Root wrapper, then tree depth 23 | 25 |
| PIOP gamma / `hash_fpp` | PIOP-input wrapper, then DECS | 26 |
| Tree depth `d+1` | One or two tree-depth-`d` children | Decreasing |
| Tree depth zero | Strict leaf only | One |

The recursive algorithm has an explicit finite fuel argument.
`source_next_height_decreases` checks the stage-height decrease, and
`extractDecs`/`extractPiopGamma` use the exact 25/26-record budgets. These are
classical finite algorithms; efficient reversible implementation and gate bounds
remain separate. No dense tree is materialized by the verification commands.

## Actual raw-byte parser

`parseFramed` reads the common source framing: profile length and bytes, role
length and bytes, raw-word count, raw words, and counter. It requires the exact
SMZ9 profile, counter zero, and no trailing bytes. Every length is checked
against the actual input by `readFixed` before its corresponding slice is taken.
`source_key_framing_roundtrip` proves round-trip parsing of the existing
`RawSha512OracleKey.preimage` constructor, with the natural 64-bit length bounds.

The source role parser is specific, not an arbitrary supplied edge relation:

- A strict leaf has 1,280 payload bytes: four salt words, one index, eight
  unreduced tape words, count 140, 140 canonical field words, count five, and
  five canonical field words. The index must be below `2^23`. Its outgoing
  digest set is empty.
- A binary node has exactly 128 payload bytes and contributes its two raw
  64-byte child digests. The source's unary-node primitive has 64 bytes and
  contributes one. The active power-of-two full tree uses the binary case.
- A root wrapper has at least 96 payload bytes. Its single outgoing digest is
  the 64 bytes immediately after the 32-byte salt. Trailing binding words are
  retained but never treated as child digests.
- A PIOP-input wrapper has at least 15,584 payload bytes: one raw root-wrapper
  digest and `5 * 388` canonical DECS response coefficients, followed by any
  binding words. Its only outgoing digest is its first 64 payload bytes.
- All other roles and malformed encodings contribute no children.

The raw framing itself enforces word alignment. No salt, tape, response
coefficient or arbitrary binding substring is counted as an outgoing hash
reference. Digest bytes are never reduced modulo Goldilocks.

The wrapper parser intentionally accepts a superset of a fixed statement's
binding grammar: it checks the minimum root/PIOP layout, not the application's
exact trailing binding length or content. This is sufficient for extraction
stability and child arity, but is not an exact accepted-bytes parser. Restricting
those wrappers to the fixed public context is a separate deterministic check.

These choices correspond to `smallwood_engine.rs`:
`concrete_smallwood_sha512_oracle_query_v1` at 4237,
`transcript_xof_digest` at 4526,
`pcs_commit_transcript_words` at 10377,
`strict_zk_merkle_leaf_words` at 11607,
`hash_merkle_root_with_binding` at 11825, and
`hash_merkle_children_at` at 12990. The mathematical parser/constructor
roundtrip does not by itself prove a compiled-Rust execution refinement.

## Why the bound holds

If the new output is neither a requested target nor a parsed child digest in
the old database, every preimage lookup at an old reachable target is unchanged.
Its selected preimage and full payload therefore remain identical. Induction
through its old outgoing edges proves that the entire extraction trace is
unchanged. This is the proved
`changed_extraction_implies_target_or_child` theorem.

The old outgoing digest set has cardinality at most `2 |D|`, by the proved
source arity lemma and a finite union bound. The target set has cardinality at
most `j`. Counting fresh outputs in this union and dividing by the exact
`2^512` raw-output cardinality proves the probability inequality; no probability
bound is supplied as a hypothesis.

`source_classical_instability_three_t` gives the resulting `3t/2^512` bound.
`source_observed_instability_three_t` proves the same bound after arbitrary
deterministic postprocessing of the complete trace, including missingness
flags, wrapper response/context projections, and default source completion.
That postprocessing cannot become unstable when its input trace is unchanged.

The fresh-key/single-valued conditions identify the intended compressed-database
insertion operation. They are not necessary for the stronger set-insertion
counting lemma. Fresh uniform output sampling is essential; a conditioned or
already recorded output does not automatically have this law.

## What remains for the quantum theorem

CDHZ Theorem 5.4 bounds a suitable coherent partition-controlled unitary's
squared commutator norm by 80 times its classical instability. Its unitary,
workspace, oracle-commutation and query-accounting hypotheses must still be
instantiated; this Lean module does not invoke them as an unproved axiom.
See the [primary paper](https://eprint.iacr.org/2025/2166), Definitions 5.2–5.3,
Theorem 5.4 and Theorem 8.4.

In particular, a physical coherent evaluation/uncomputation of this extractor,
an efficient sparse implementation, consistency with final accepted openings,
collision/error accounting, live raw expansion/state-restoration mapping, and
the decoder's actual round-by-round failure bound remain separate. Leaf salt
and path-index agreement with the authoritative wrapper must be checked in the
opening-consistency adapter; the trace retains all necessary raw fields.
Twenty final verified openings must not be substituted for a prefix database.

## Verification

Use the cached direct check, with one Lean process and no shared-cache mutation:

```sh
cd formal/crypto
lake env lean -DwarningAsError=true \
  -o /tmp/SmallWoodV8Smz9CoherentMerkleGeometry.olean \
  HegemonCrypto/SmallWoodV8Smz9CoherentMerkleGeometry.lean
```

The finite extractor, raw-key framing roundtrip, source parser geometry,
`3t/2^512` bound and deterministic postprocessing lemma passed this strict
check. Five endpoint audits reported only `propext`, `Classical.choice` and
`Quot.sound`. No additional cryptographic assumptions enter these classical
combinatorial theorems.
