# Eager public leaf-oracle game: exact encoding and remaining source boundary

## Scope and verdict

`SmallWoodV8Smz9EagerOracleGame.lean` supplies a witness-free eager public
leaf-program constructor, an abort-preserving chronological transport using the
existing source-sized polynomial callbacks, and a physical full-table to public
opened-table reduction. It is not yet a whole serialized SMZ9 privacy theorem.

The imported `EagerSimulator.PublicPiopParameters` still uses the older
`ProductionConstraintExpression` syntax. The live 8,271-expression
`FieldExpression` program, including inverse and selector nodes, is not silently
identified with that syntax. The live program adapter is a separate obligation.
The theorem name `source_instantiated_eager_algebraic_output_law` in the imported
module does not discharge this obligation.

The public leaf constructor takes public PIOP parameters and responses, opening
points, DECS coefficients, independently sampled remaining view coordinates,
the non-leaf index selector, salt, digest labels and revealed leaf tapes. It has
no witness or old PIOP mask input. Its full tape-table argument has no effective
dependence on unopened coordinates, as proved below. Witness-dependent inverse
coins and the source completion table occur only on the comparison side.

## Canonical raw leaf encoder

The encoding follows `circuits/transaction/src/smallwood_engine.rs`:

- `concrete_smallwood_sha512_oracle_query_v1`, line 4237: profile and role length
  framing, literal bytes, raw-word count, eight-byte little-endian raw words,
  and counter.
- `strict_zk_merkle_leaf_words`, line 11607: salt words, index, tape words, data
  count and rows, then mask count and masks.

The Lean constructor fixes the active 53-byte profile and 42-byte leaf role,
the 160-word count, 32 salt bytes, 64 tape bytes, 140 data fields, five mask
fields, and zero counter. Its 1,407 raw bytes are partitioned as follows:

| Offset | Length | Content |
| --- | ---: | --- |
| 0 | 151 | Framed profile/role, 160-word count and salt |
| 151 | 8 | Canonical leaf index |
| 159 | 64 | Unreduced leaf tape |
| 223 | 8 | Data count 140 |
| 231 | 1,120 | 140 canonical Goldilocks representatives |
| 1,351 | 8 | Mask count five |
| 1,359 | 40 | Five canonical mask representatives |
| 1,399 | 8 | Counter zero |

`raw_word_bytes_little_endian` proves the base-256 value of every raw word.
`canonical_field_bytes_value` and `canonical_field_bytes_injective` prove that
field bytes encode the canonical representative without collisions.
`canonical_leaf_index` and `canonical_leaf_tape` recover the original index and
tape from the complete raw constructor. This is a mathematical byte-array
constructor corresponding to the source operations, not a proof about compiled
Rust execution, SHA-512, the operating-system RNG, or architecture-dependent
execution.

## Public reconstruction and actual table identities

The field decoders recover W openings, the nonlinear and linear mask openings,
and the next-column PCS partials from `EagerAlgebraicFields`. The proved
`eager_field_decoders` theorem checks their exact positions in the 696 scalar
and 40 partial arrays. `rowsFromFields` then reconstructs all 140 opened DECS
rows from the same 12 combination tails and 128 subset coordinates. The five
DECS mask fields are reused verbatim; neither the data rows nor masks are
resampled by the encoder.

`IndexedTargets` binds the twenty indices to the actual disjoint-coset point
formula, requires distinct indices, and carries the already established LVCS
admissibility predicate. `eagerContext` keeps both these indices and the public
fields. `partial_context_abort_projection` proves that the optional late abort
has exactly the same public outcome as the uniform-view simulator. `none`
means no opened programs, not conditioning on successful selection.

`publicOpenedInputs` encodes the twenty selected rows and their tapes.
`public_opened_inputs_only_revealed_tapes` proves that changing any unopened
tape cannot change that table. `publicOpenedOracle` answers each encoded input
with the sampled label indexed by its decoded index; every other query goes
to the supplied previous oracle. In particular, removing a current unopened
program restores a prior proof's value if that value was previously present.
It does not replace the prior oracle by zeros or by a fresh oracle.

The physical continuation is a fixed public-context/opened-tape-generated
circuit in the comparison. Its initial state and interquery isometries must not
be instantiated from hidden witness coins. Merely packaging an arbitrary state
as `PublicContinuation` does not prove its provenance. The terminal measurement
may be controlled by the retained classical tape label, as allowed by the
imported cq bound; this does not expose that label to earlier oracle queries.

`public_suffix_support_is_exact` identifies the literal encoded-input set with
the source-shaped support used in the hidden-patch theorem.
`public_atomic_kept_oracle_is_serializer` identifies `keepOpenedPrograms` on a
genuine physical `AtomicReference` with this exact public opened-oracle
constructor. These are function/table equalities, not names assigned to games.

## Chronological law and physical comparison

`source_eager_oracle_context_law` instantiates the source-sized
`sourcePcsBaseForTranscript` and `sourceCommittedHeadsForTranscript` callbacks
inside the remaining-coin transport. Its right side uses a uniform remaining
view and fresh tapes with the witness-free context constructor. The observation
is arbitrary: it can retain all public fields, the complete opened oracle,
prior entries, salt, labels and subsequent computation. The equality preserves
abort. No independence of a witness-dependent frozen source context is assumed.

This law is conditional on the already sampled outer response/challenge
material. The earlier joint Q/M change of variables, including its correlated
original coins, is proved in the imported eager-privacy and game-composition
modules. A theorem that instantiates and composes both stages with the live
program and all serialized output is still required; a fixed-fiber equality
must not be promoted to that whole-game claim.

`completedAtomicReference` fills the remaining suffix table on the comparison
side. `completed_table_to_public_reference_bound` uses the previously proved
physical hidden-patch result to compare that full programmed table against the
public opened-only reference with loss

`hiddenPatchLoss(q) = 2 sqrt(4 q^2 2^-512) = 4 q 2^-256`.

Its remaining deterministic premise says that the completion's suffix agrees
with the public suffix at every opened index. It does not accept a privacy
distance, simulator equality, or whole-view indistinguishability premise.
Nevertheless this suffix equality must actually be discharged for the live
source; it is not an automatic consequence of the probability theorem. The
physical circuit contains complex-linear isometries, coherent full-domain
oracle queries, arbitrary workspace, and a terminal Born measurement. All
oracle calls in the continuation must be counted. No stronger discarded-secret
quadratic bound or trace-distance equivalence is claimed.

## Remaining deterministic source composition

The imported modules separately prove mask recovery, recovery of the 736 PCS
column evaluations from their source scalars/partials, equality of public
combination heads with the source column polynomial values under the degree
bound, 140-row reconstruction, and DECS mask reconstruction. The final live
adapter must compose these facts and discharge the actual column degree bounds
to prove the opened-suffix equality for the honest completion table.

Further obligations remain for the live arithmetic program, exact raw
serialization/refinement, the actual non-leaf selector execution, atomicity and
randomness chronology, the initial/final external QROM transitions, complete
history accounting including aborted/unpublished batches, and concrete hash/RNG
and release authority. None is credited by the local theorem merely compiling.

## Local verification

Direct cached command, without a shared build or generated inventory mutation:

```sh
cd formal/crypto
lake env lean -DwarningAsError=true \
  -o /tmp/SmallWoodV8Smz9EagerOracleGame.olean \
  HegemonCrypto/SmallWoodV8Smz9EagerOracleGame.lean
```

The complete module, including the completed-table comparison, passed the
strict check with `warningAsError=true` and `autoImplicit=false`, followed by
the central cached build (2,653 jobs). This removes the earlier unchecked
completion-lemma status. Its explicit source-suffix correspondence premise
still needs the current-program opening binding; compilation alone does not
establish the full source experiment.
