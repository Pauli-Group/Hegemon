# Current SMZ9 public CSR and statement context

Status: successor-count update strict checks PASS in all three affected Lean
modules; 49 principal axiom audits PASS (18 public-context, 10 QROM accounting,
21 adaptive accounting). Dependencies are at most `propext`, `Classical.choice`
and `Quot.sound`; exact groups are recorded below. This closes the previous free linear-weight/target premise
of `SmallWoodV8Smz9CurrentPrivacyGame`; it is not a complete production privacy or
Rust-execution refinement certificate.

## Concrete public constructor

`SmallWoodV8Smz9CurrentPublicContext.lean` imports the current privacy game, exact
generated-program canonicality and the existing CSR interpreter-to-field bridge.
It fixes the actual 565-node public expression DAG and all 20,605 generated CSR
attempts. `statementParameters` obtains its 120 public words by executing
`encodePublicStatement statement`; an arbitrary public map is not an argument.

The constructor runs `evalExpressionNodes publicWords [] exactCsrExpressions`.
Consequently equality selectors, bit extraction, inverses, flags and hash-role
selector expressions use the actual public-only grammar. There is no witness
row input. `accepted_public_selector_equations` derives every actual node
equation. Successful packed acceptance supplies the real trace, its exact length
and in-range coefficient/target lookups; the total `getD` notation never replaces
a missing lookup on this accepted domain.

`denseCoefficient` adds all duplicate term coefficients at each of the 43,904
row-major packed coordinates in Goldilocks. This represents the coefficient
function of Rust's normalized `BTreeMap`; zero coefficients disappear and
duplicate cancellations are retained. `dense_coefficient_dot` proves that its
finite dot product equals the actual sparse interpreter field sum. The concrete
generated canonicality theorem supplies all coordinate bounds.

`retainedAttempts` filters the original ordered attempt list after public
specialization. It drops exactly a zero coefficient function with zero target.
For a retained empty/nonzero row, `normalizedCoefficient` uses source coordinate
41,528, the `tail_source_index(120)` fallback. On accepted packed relations this
branch is impossible: the actual original row equation already forces a zero
target if all coefficients vanish. This is proved, not assumed. Natural target
zero and field target zero coincide because the real public trace is canonical.

The sublist theorem preserves generated row order. Linear batching indexes gamma
by the retained row position, not `attempt.globalIndex` or `attempt.localIndex`.
The nonlinear and linear batches use one shared gamma stream, as the source does.

## Correct gamma sampling width

The source samples

```
width = max(830, retainedAttempts.length)
requested_words = 5 * width
```

This is `batchingWidth` and `batchingSampleCount`. `gammaFromSamples` consumes a
flat vector of exactly that length, laid out as five consecutive `width`-word
rows. Separate proved endpoints show that every nonlinear root and retained
linear row indexes an actual supplied sample. The total fallback outside the
width is never used by either batch. `batching_sample_count_le` proves an upper
bound of 103,025 requested field words from the fixed 20,605-attempt inventory.

The successor Rust source report's realized request is a different quantity:
102,545 words, a cap of 102,584 candidates (12,823 eight-word blocks), and
`102584 - 102545 + 1 = 40` minimum rejections on exhaustion. For this fixed
tuple, exact integer arithmetic gives a binomial bound of 773 bits per request,
or 748 bits after the `2^25` request union; the next bit fails in each case.
The two exact accounting modules retain this realized tuple. QROM accounting
keeps its looser 500-bit compositional envelope; adaptive finite accounting's
`C^k` envelope is different from the exact binomial term (589 bits for this
tuple). The successor Lean checks passed, including the exact 748-bit bound and
failure of its 749-bit successor in QROM accounting.

Neither 102,545 nor the 748-bit result replaces the universal 103,025-word
constructor ceiling. A shorter request changes the cap slack: for example,
the arithmetic request length 102,520 gives 102,552 candidates and 33 minimum
rejections, with a 604-bit union-adjusted binomial bound. This is an arithmetic
counterexample to inferring a uniform 748-bit bound from a length ceiling alone,
not a proof that this exact shorter length is emitted by a valid statement.
The separate variable-length sampler-family bound and source refinement must
cover every actually reachable request length.

The older description of current gamma sampling as `5*830 = 4150` and 523 raw
512-bit blocks is not the full active CSR configuration. Source inspection shows
that the first `base.raw_replicate` family alone has 15,561 Always rows, each
equating a nonzero packed lane with lane zero using coefficients 1 and -1.
Therefore successful source compilation already requires at least 77,805 gamma
field words and at least 9,730 raw blocks under `ceil((requested+32)/8)`. This
source-inspected lower bound is distinct from the Lean-certified upper bound.
The sampler proof must use the actual statement-dependent request count and
preserve its own failure result; a 4,150-word illustrative instance does not
charge the full current gamma oracle work.

Source anchors:

- `circuits/transaction/src/smallwood_engine.rs:11929`, `derive_gamma_prime`,
  uses `rho * max(constraint_count, linear_constraint_count)` and chunks by that
  common width.
- `circuits/transaction/src/smallwood_poseidon2_v8_semantics.rs:4099`, adapter
  geometry uses the specialized CSR target count.
- `circuits/transaction/src/smallwood_poseidon2_v8_program.rs:383` and
  `smallwood_poseidon2_v8_semantics.rs:1314`, the first 15,561 raw replication rows.
- `smallwood_poseidon2_v8_semantics.rs:2736`, exact public-expression
  specialization, normalized duplicate collection, retention and zero fallback.

## Public abort is not conditioned away

Rust's CSR cursor rejects an Always-family attempt if specialization would drop
it. Serialized emission zero denotes that rule. `alwaysRowsEmitted` is an
explicit public check, and `compilePublicParameters` returns `none` on either
expression-evaluation failure or this emission-guard failure. It returns only
the computed `publicParameters`, never caller-supplied weights.

`compiled_public_parameters_are_generated` identifies every successful result.
Both public failure cases have direct abort-preservation theorems.
`public_compiler_abort_preserves_bound` composes a source/reference bound with
this public `Option` result using the same failure observation on both sides.
It does not condition on compiler success, retry or resample. The theorem does
not assert that every semantically admitted public statement passes every
Always-emission guard; preserving public failure makes that an unnecessary
privacy premise.

## Direct privacy integration

`packingValues` converts the same canonical packed witness to the actual
686-by-64 field assignment. `source_packing_rows_match_packed_lane` proves that
canonical natural representatives recover the exact interpreter lane lists.

`canonical_statement_supplies_current_game_algebra` derives both previous game
premises from one `CanonicalPublicPackedDomain`:

1. The actual 8,271-node, 830-root interpreter accepts all 64 source lanes.
2. Each of the five generated linear weighted sums equals its generated target.

The direct one-witness endpoint is
`canonical_statement_current_privacy_bound`; its source and explicit public
reference differ by at most `hiddenPatchLoss(q) = 4*q/2^256`.
`canonical_statement_two_witness_current_privacy_bound` compares two accepted
packed witnesses of the same admitted encoded statement with loss at most
`2*hiddenPatchLoss(q) = 8*q/2^256`. The public reference contains no packed witness.
The public-compiler abort theorem composes with either endpoint without adding
loss or a factor for the number of retained rows, contexts or source coins.

## Remaining boundaries

- The field-level normalized coefficient function and the actual fixed program
  are bound. A universal theorem that Rust's byte parser, `BTreeMap`, cursor,
  public admission and execution refine this Lean constructor remains separate.
- The shared gamma values are public parameters at this stage. Their derivation
  from the exact raw capped sampler and full public transcript must be composed
  using the correct statement-dependent sample count above.
- The raw LVCS hash-index/admissibility sampler is not changed here. Its existing
  indexed chooser returns an admissible target or failure.
- Earlier chronological public-response generation, the honest-to-randomized-
  label QROM hybrid and later extraction/production authority remain separate.
- The physical reference state/oracle is fixed before fresh hidden leaf tapes.
  Query bounds still charge every future full-oracle query, including internal
  honest calls. No non-query continuation may conceal additional oracle calls.

No runtime, verifier predicate, proof carrier, release gate, randomness source,
network state or retained production artifact was changed.

## Verification

From `formal/crypto`:

```sh
lake env lean -j1 -M3072 -DwarningAsError=true -DautoImplicit=false HegemonCrypto/SmallWoodV8Smz9CurrentPublicContext.lean
```

An independent read-only source-order spotcheck confirmed public-only selector
evaluation, duplicate normalization, zero fallback, retained-row indexing and
the shared gamma stream. It made no edits or builds.

The 18 public-context endpoint audits covered the dense sparse-sum bridge, actual coordinate
bounds, accepted-row nonemptiness, the full linear batch, public root and selector
equations, lane conversion, both exact finite sample accesses, the sample-count
bound, generated compiler success, public abort composition, both derived game
admission premises and the direct one-/two-witness privacy endpoints. Strict
source and audit runs for the successor inventory passed on 2026-09-07. The
accounting chain then passed with the same flags:

```sh
lake env lean -j1 -M3072 -DwarningAsError=true -DautoImplicit=false HegemonCrypto/SmallWoodV8Smz9QromAccounting.lean
lake env lean -j1 -M3072 -DwarningAsError=true -DautoImplicit=false -o .lake/build/lib/lean/HegemonCrypto/SmallWoodV8Smz9QromAccounting.olean HegemonCrypto/SmallWoodV8Smz9QromAccounting.lean
lake env lean -j1 -M3072 -DwarningAsError=true -DautoImplicit=false HegemonCrypto/SmallWoodV8Smz9AdaptiveFiniteAccounting.lean
```

Only the explicitly authorized QROM `.olean` was refreshed. Audits used stdin
streams with `#print axioms` under the same strict flags; no audit directives
were added to the source files. No new project axiom, placeholder, native
evaluator, runtime mutation, or release authority was introduced.

The exact legacy diagnostic maxima remain 621,728,502, 4,166,198 and 2,090,101.
Each still passes its 128-bit arithmetic bound and each successor fails. These
are the existing conditional diagnostic maxima, not protocol-lifetime limits.

Checked source SHA-256:

- `SmallWoodV8Smz9CurrentPublicContext.lean`:
  `1f66ba65a0a6e2ecbaccd174df526b306afc1935d7a5adbc00ffe8efce4db6cd`.
- `SmallWoodV8Smz9QromAccounting.lean`:
  `b287fd9d09c861bd2765313b8b569d1c580f48e73b8eb71164240ea705e03e28`.
- `SmallWoodV8Smz9AdaptiveFiniteAccounting.lean`:
  `c0f7f8d7981603d3ee8731fc1ae9961111daea9eb03ede3a187eaa3b06b023f5`.


## Exact principal axiom outputs

Names below are relative to `HegemonCrypto.SmallWood` and the indicated module
namespace. Each group lists the exact dependency set returned by Lean.

`V8Smz9CurrentPublicContext`: [propext, Classical.choice, Quot.sound].

```text
dense_coefficient_dot
exact_attempt_coordinates_bounded
nonlinear_gamma_sample_is_present
linear_gamma_sample_is_present
batching_sample_count_le
accepted_retained_row_nonempty
accepted_public_linear_batch
accepted_public_roots_resolve
accepted_public_selector_equations
retained_attempts_preserve_source_order
source_packing_rows_match_packed_lane
compiled_public_parameters_are_generated
public_expression_failure_preserves_abort
always_family_failure_preserves_abort
public_compiler_abort_preserves_bound
canonical_statement_supplies_current_game_algebra
canonical_statement_current_privacy_bound
canonical_statement_two_witness_current_privacy_bound
```

`V8Smz9QromAccounting`: no axioms.

```text
field_xof_minimum_rejections_matches_cap
exact_abort_and_no_grinding_parameters
```

`V8Smz9QromAccounting`: [propext, Classical.choice, Quot.sound].

```text
exact_field_xof_abort_ratio_numerator
exact_field_xof_abort_ratio_denominator
exact_field_xof_abort_supports_748_bits
exact_field_xof_abort_does_not_support_749_bits
exact_field_xof_abort_is_bounded_by_conservative_envelope
conditional_global_query_finite_history_at_2pow128_is_below_half
conditional_global_query_finite_history_at_2pow142_is_below_half
conditional_global_query_finite_history_at_2pow143_is_not_below_half
```

`V8Smz9AdaptiveFiniteAccounting`: no axioms.

```text
exact_field_xof_sampler_parameters
```

`V8Smz9AdaptiveFiniteAccounting`: [propext, Classical.choice, Quot.sound].

```text
choose_abort_numerator_le_pow_envelope
```

`V8Smz9AdaptiveFiniteAccounting`: [propext].

```text
conditional_one_proof_supports_157_bits
conditional_one_proof_does_not_support_158_bits
conditional_analysis_history_supports_136_bits
conditional_analysis_history_does_not_support_137_bits
four_152_bit_external_terms_one_proof_supports_149_bits
four_152_bit_external_terms_one_proof_does_not_support_150_bits
four_152_bit_external_terms_history_supports_128_bits
four_152_bit_external_terms_history_does_not_support_129_bits
four_151_bit_external_terms_history_supports_127_bits
four_151_bit_external_terms_history_does_not_support_128_bits
exact_conditional_maximum_proofs_at_128
conditional_maximum_supports_128_bits
conditional_maximum_successor_does_not_support_128_bits
exact_four152_maximum_proofs_at_128
four152_maximum_supports_128_bits
four152_maximum_successor_does_not_support_128_bits
exact_four151_maximum_proofs_at_128
four151_maximum_supports_128_bits
four151_maximum_successor_does_not_support_128_bits
```
