# Current SMZ9 chronological and quantum privacy composition

Status: direct strict check and 23-principal-endpoint dependency audit passed on
2026-09-07. Every audited endpoint uses only `propext`, `Classical.choice` and
`Quot.sound`; no new axioms or proof placeholders occur. This includes the
shared-lifetime embedding and executed chronological source experiment. It does
not assert completed adaptive repeated whole-prover privacy or production authority.

## What the new composition actually constructs

`SmallWoodV8Smz9CurrentPrivacyComposition.lean` uses the current generated public
CSR/statement constructor and actual physical source-column interpolation.

`currentJointHeads` constructs all committed heads from the same witness
interpolation coins, original PIOP masks and source PCS coins.
`currentJointUnmasked` evaluates the actual current-program PIOP response offset
at the generated DECS response `D`, using `statementParameters` and its shared
gamma stream. Thus the affine map is the real dependency-ordered map

```
D = DECS_unmasked(heads(W, Q, PCS), LVCS_tails) + M
T = PIOP_unmasked(statement, batching(D), W) + Q
```

The proof is not a declaration that two arbitrary transcript distributions are
equal. The existing finite bijection computes the inverse in the opposite order:
recover `Q` from `D,T`, rebuild the original heads and recover `M`.

The inverse/forward source-suffix theorems identify all raw 140-row and five-mask
leaf payloads with `currentSourceSuffix`. Importantly,
`current_forward_suffix_is_target_independent` shows that the inverse expressions'
apparent dependence on fresh labels through `D` and PIOP batching disappears:
they reconstruct the exact originally sampled `Q/M` suffix. It is not a
target-first programmed-input entropy argument.

`original_current_leaf_input_max_mass` then specializes the genuine 1,407-byte
input constructor to those original source fields. The newly sampled 64-byte
tape has maximum input point mass `2^-512`. This establishes the point-mass
ingredient only, not the external adaptive quantum distance theorem.

## Chronological physical mixtures

`chronologicalRandomizedAcceptance` samples remaining W/PCS/LVCS coins, then
the original Q/M masks, then an independent full leaf-label table. It computes
`D,T` using the actual affine map above and invokes the current physical
source-context experiment. The original suffix theorem justifies the latter's
inverse-coordinate representation of the same physical programmed inputs.

The real finite-mixture transport preserves arbitrary observations of the old
masks and new outputs. It first moves to fresh public `D,T`, then the existing
current source-coordinate and hidden-table theorem supplies the public reference.
There is no conditioning on a successful sampler branch and no factor equal to
the number of source coins, labels, contexts or outputs.

`PublicStageGenerator` depends on public labels and `D`; it returns either an
admissible public geometry with an actual quantum continuation, or `none`.
The continuation is generated from the public context and visible leaf tapes.
Its initial state and query steps have no hidden-current-tape argument. Index
selection keeps its additional existing `Option` failure result.
`guardedPublicStageGenerator` executes the encoded-statement public compiler
guard first; its failure has a direct stage-abort theorem. Applying the generated
game theorem to this guarded generator retains both public failure levels.

`generated_randomized_source_to_public_reference_bound` derives the current
bound from one `CanonicalPublicPackedDomain`, including actual packed nonlinear
acceptance and the generated CSR linear equations:

```
|chronological randomized source - generated public reference|
    <= hiddenPatchLoss(q) = 4*q/2^256.
```

The source/reference observations agree exactly on a public stage abort. No
failed request is silently resampled or removed from the experiment.

## One persistent physical oracle

`LifetimeProgram` is a concrete finite program syntax. It contains local
complex-linear isometries, the actual full coherent XOR oracle query, classical
honest reads, individual programming events, finite simultaneous table updates,
normal termination and public abort. Its execution returns the actual final
oracle, quantum state, abort flag and executed resource counts. There are no
probability fields or axioms in the program or result type.

`runLifetime` threads the same oracle and state through every operation.
Local gates cannot inspect an oracle argument. Honest reads use the current
table and choose the next program from the returned value. Programming preserves
all other entries; multiple updates apply in order. Even a public abort retains
the current table and state in the result. Quantum and local operations preserve
Hilbert norm; normalized inputs and a valid failure observation produce a valid
Born probability.

`lifetimeAcceptance` samples a single initial random oracle for the entire
lifetime. Private initial coins are independently sampled; the initial-state
constructor has no oracle-table argument. Oracle-correlated setup advice must
instead be constructed through charged program queries.

`compileQuantumCircuit` embeds the existing current-game circuit into this
syntax and proves exact state continuation, oracle continuation and query count.
`sourceLeafProgramEntries` represents the current actual raw leaf overlay.
`source_table_program_is_full_source_overlay` and
`compiled_source_table_continues_current_circuit` show that programming these
entries and executing the current circuit gives its actual `fullSourceOverlay`
state, while passing the same updated oracle to an arbitrary next program.
The finite table operation models an atomic group of local writes; it is not an
uncharged oracle-reading primitive.

`executedAtomicProgram` additionally compiles the final tape-dependent local gate
and identifies its actual Born observation with the existing source branch.
`executed_full_source_is_current_experiment` proves equality of the complete
finite hidden-tape mixture, not merely equality of a table-update operator.
`executedGeneratedSourceObservation` keeps the exact public stage abort and
opened-tape mixture while using these executed branches. Finally,
`executed_chronological_source_is_generated_game` identifies the complete
generated randomized-label chronological experiment with its executed physical
program mixture, and `executed_chronological_source_to_public_reference_bound`
derives the same `4*q/2^256` bound without a game-equality or distance premise.

This is a concrete source-experiment splice, not the honest-hash transition:
the previous table and state are the existing continuation's actual fields.
Compiling an adaptive prior execution to those fields and all subsequent
measurements/reads is still required for each whole-lifetime hybrid.

## External honest-hash transition and repeated scope

`honest_current_public_privacy_bound` takes an explicitly named
`externalHonestReprogramming` hypothesis about two computed experiments:

- The actual shared-table `LifetimeProgram` execution and its Born observation.
- The generated chronological randomized-label source above.

It derives a bound to the generated public reference of
`reprogrammingLoss + hiddenPatchLoss(q)`. It does not postulate this as a project
axiom, put it into a probability-bearing receipt or derive it from point mass
alone. The existing [honest-leaf reduction](hidden-leaf-qrom-step.md) identifies
the published adaptive-reprogramming theorem and the separate applicability,
freshness, rescheduling, read-after-program and finite-QROM obligations.
The hypothesis currently asks for the full named experiment distance; it is not
yet a checked instantiation of that published theorem. In particular, calling
the premise external does not discharge the adapter from the actual honest
program to the chronological randomized-label source. The executed-source
identity above closes the latter endpoint's interpretation, not that adapter.

`shared_lifetime_hybrid_composition` telescopes an actual family of executed
lifetime programs with one common initial table/coin space and observation. Its
bound is the sum of the justified adjacent whole-lifetime losses. It does not
restart the oracle between proof invocations.

The operator embedding closes the fixed-circuit/local table-splice mechanics.
It does not yet compile the entire adaptive source prover, its measurements,
all future honest calls and every hybrid splice into that program family.
Accordingly the repeated theorem still requires adjacent bounds for those full
programs. The current one-invocation theorem cannot simply be applied to
independently restarted calls and declared a repeated quantum proof.

## Query and release boundaries

`lifetimeOracleExposures` counts coherent queries plus classical honest reads.
Both constructors increment the actual executed count, including calls before a
later abort. Programming points have a separate counter. The two-query
leaf-domain simulation budget charges twice the whole lifetime exposure count.
All raw sampler/XOF counter queries must be represented and charged; source
SHA-512 compression rounds are not separate random-oracle queries.

In particular PIOP gamma sampling uses the corrected count
`5 * max(830, retained CSR rows)`, not 4,150 words. The exact finite sample-vector
interfaces are in `SmallWoodV8Smz9CurrentPublicContext`. Failed or unpublished
proof attempts reaching a leaf batch still incur their queries and programs.

Remaining obligations include the external adaptive-reprogramming theorem's
application to the exact source experiment; full lifetime source-program and
byte/query-sampler refinement; concrete RNG and SHA-512 replacement; typed-valid
witness to honestly packed accepted relation completeness; and independent
security/release authorization. The present domain starts with admitted public
data plus actual `AcceptsPacked`; it does not replace the security contract's
typed-witness relation with that stronger premise silently.

No runtime code, verifier predicate, proof bytes, release gate, production
artifact, network state or authority was changed.

## Verification command

From `formal/crypto`:

```sh
lake env lean -j1 -M3072 -DwarningAsError=true -DautoImplicit=false HegemonCrypto/SmallWoodV8Smz9CurrentPrivacyComposition.lean
```

Checks are coordinated centrally to limit aggregate Lean memory pressure.
The initial direct-unfolding proof reached the memory cap; the final proof uses
generic runner projections and a bounded congruence step, without increasing
that cap. Temporary endpoint-print commands were removed after the audit.
