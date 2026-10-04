# Atomic privacy-game composition: checked boundary

## Result

`SmallWoodV8Smz9PrivacyGameComposition.lean` connects the source-shaped hidden
patch bound to a generated classical context and opened-tape experiment. The
operational endpoint is `atomic_full_vs_opened_reference_bound`:

\[
|\Pr[\text{full programmed oracle accepts}]
 -\Pr[\text{opened-program-only reference accepts}]|
 \le 2\sqrt{4Q^2\,2^{-512}}=4Q\,2^{-256}.
\]

The probabilities explicitly average the generated public context, revealed
leaf tapes and fresh hidden tapes. They retain arbitrary quantum workspace and
a final physical isometry/Born measurement. `Q` bounds every raw-oracle call in
the entire remaining continuation, including future honest invocations,
verifier work and adversarial queries. It is not only the adversary's calls
before the current proof, or only the calls between two messages.

No whole-view distance or game-equivalence proposition is stored in the
`AtomicReference` structure. Its fields are actual oracle functions, source
leaf payloads and target digests, a normalized state, complex-linear isometric
circuit gates, a query count and final measurement data. The local operational
bound is instantiated from `HiddenPatch`, then averaged with the actual finite
PMF weights. There is no number-of-leaves or number-of-contexts factor.

## Freshness is derived from a product experiment

For an arbitrary previously generated context law, the opening set is selected
as a function of that context. Only then is a fresh uniform full tape table
split by the selected set. An explicit equivalence restricts the table to
opened and unopened coordinates, and its inverse recombines them. The checked
`generated_context_has_fresh_hidden_tapes` equality retains arbitrary
observations of both halves and any reference state generated from the context
and opened tapes. Its right-hand experiment generates that reference before
sampling an independent uniform hidden half.

This avoids conditioning-on-success or informal entropy arguments. The
selector may return `none`; `openedOrEmpty none` is exactly the empty set, so
an aborted invocation reveals no leaf tapes and all its leaf programs remain
in the removable support. An invocation that reached leaf programming still
counts toward the honest programming and later-query budgets even if it aborts
or its proof is never published.

The source's chronological remaining-coin transport is composed directly using
`EagerPrivacy.source_remaining_partial_chronological_joint_law`. This includes
the actual witness-opening map, corrected next-column PCS map, LVCS feedback,
and the optional late opening selection. `source_partial_context_conditional_tape_law`
then appends the exact fresh opened/hidden tape split to that derived law. The
arbitrary public-context function has no tape argument. The earlier Q/M
chronological transport is also extended with the complete fresh tape table,
while retaining original masks and correlated leaf inputs. These two exact
source transports are available separately; instantiating their shared
head/offset functions and the complete witness-free public constructor remains
necessary. This module does not claim every source computation producing
that constructor has already been refined.

For the typed adaptive non-leaf program, the existing literal role separation
theorem proves that leaf overlays do not change its complete trace or its
opening selector. The new composition retains this exact selector equality.
Applying it to Rust still requires the actual atomic program to use the
verified non-leaf roles and not to read fresh tapes when selecting the public
context. Arbitrary external quantum queries are not moved across the atomic
invocation; they are handled by the full raw-oracle continuation theorem.

## The oracle tables are actual tables

`source_opened_overlay_independent_of_hidden` proves that the opened-program
table depends only on the revealed tape half. `fresh_hidden_padding_observation`
justifies adding independent dummy coordinates on opened indices. The actual
unopened source overlay is unchanged by this padding.

`source_opened_then_unopened_is_full_overlay` proves literal function equality:
programming opened indices, then unopened indices, yields the original full
source-shaped leaf overlay. `keepOpenedPrograms` constructs the opened-only
reference oracle, and `kept_opened_reference_recovers_full_table` binds its
physical extension to the original full raw oracle, including the unchanged
non-leaf input partition. The final acceptance theorem uses this identity;
the two games are not merely given suggestive names.

## What is not closed by this module

The following are independent obligations, not hidden premises receiving
security credit here:

- The initial honest-hashing to independently randomized labels transition,
  and any final adaptive-reprogramming transition required by the selected
  simulator, use external QROM theorems. Their hypotheses and programming/query
  counts must be checked separately; this module does not certify them.
- The public simulator must instantiate the public-context function with its
  witness-free recovered algebraic fields, retain the exact opened-row/DECS-mask
  correlations, and construct the corresponding reference state/circuit.
  The separate `EagerSimulator` work is not imported or assumed complete here.
- The actual runtime must refine the fixed, tape-independent atomic program,
  the source byte constructors, ideal fresh randomness and the physical finite
  query experiment. General channel implementations require appropriate
  dilation/refinement. Existing local field laws are not those refinements.
- Multi-invocation composition must use a bounded complete history and charge
  all reached leaf batches, failures, retained programs and future queries.
  The single-invocation bound does not itself instantiate that history.

Consequently this is a checked atomic game-composition milestone, not a
complete serialized-SMZ9 zero-knowledge certificate or production authority.
The optional stronger discarded-secret `4Q^2p` argument remains outside the
machine-checked result and is not used in the bound above.

## Reproduction

After the coordinator builds the cached `EagerPrivacy` and `HiddenPatch`
dependencies, run from `formal/crypto`:

```sh
lake env lean -DwarningAsError=true -o /tmp/SmallWoodV8Smz9PrivacyGameComposition.olean HegemonCrypto/SmallWoodV8Smz9PrivacyGameComposition.lean
```

The module is research evidence only. It does not change proof bytes, runtime
code, a production capability, the registry, or any release gate.

The 2026-09-07 strict cached check passes. Axiom audits of the generated-context
freshness law, Q/M-plus-tape transport, source partial-context tape law, literal
full/opened table identity and final atomic operational bound report only
`propext`, `Classical.choice` and `Quot.sound`.
