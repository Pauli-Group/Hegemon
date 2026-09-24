# Current SMZ9 retained-update request compiler

Status: strict Lean check and thirty principal axiom audits PASS, 2026-09-07.
All audited roots depend only on the standard foundational axioms `propext`,
`Classical.choice`, and `Quot.sound` (some need only `propext`). The already
checked `SmallWoodV8Smz9CurrentPrivacyComposition.lean` is unchanged. This checks
the compiler and concrete pivot result below, not complete adaptive privacy.

Owned implementation:
`formal/crypto/HegemonCrypto/SmallWoodV8Smz9CurrentRepeatedPrivacy.lean`.

## Concrete construction

The module replaces the future mutable-oracle primitive with a fixed baseline
oracle plus a retained finite update register inside the quantum workspace.
Every logical read, including an honest read and a lookup hit, performs exactly
two baseline queries: obtain the baseline answer in scratch, select the retained
override or that answer into the answer register, then uncompute scratch. The
answer register uses the existing XOR digest group, so the second raw query is
the same physical oracle operation as the first. Scratch starts and ends at
zero. The baseline oracle and all retained quantum state persist throughout the
compiled suffix; a request boundary does not reset either one.

The update-buffer helper implements last-record-wins lookup. A fresh-slot write
is the reversible swap of the empty symbol and the new record, not an
irreversible `Function.update` misidentified as a unitary operation. A
history-controlled version leaves the history register unchanged and chooses
its write permutation from that retained history. Freshness is an ordinary
state invariant required to interpret a swap as an append.

`RequestGrammar` contains actual oracle-independent local isometries, mutable
reads, honest address-prepare/read/answer-record triples, retained-register
permutations, and request-phase gates. The compiler expands every read into two
physical oracle calls. It is a finite coherent schedule: controlled actions may
depend on retained history, but no callback is permitted to inspect a quantum
state or the baseline oracle as classical data. Request-phase tags alone do
not establish execution of the current prover's algorithm.

The source includes a clean-scratch support predicate, automatic preservation
for mutable reads and retained writes, and a recursive preservation theorem
when local/prepare/record/phase gates preserve that subspace. The compiler's
execution identity and exact query-count identity do not depend on a privacy
distance premise.

## Connection to the current physical game

The compiled public-stage generator preserves the original `Option` result,
point geometry, selection guard, ordinary continuation data, postprocessing,
and event. Failed public compilation remains the same abort branch. The grammar
factory receives public stage/context/opened information and no pivot-hidden
tape argument. The same factory, lookup, and initial retained state must be
used on both sides. This is not permission to encode the pivot's hidden full
leaf addresses or hidden tapes in a common initial update/advice register.

`fullCurrentRequestExperiment` is the existing executed chronological
randomized-label current-source experiment with the compiled future grammar.
`publicCurrentRequestExperiment` is the corresponding generated public
reference. The principal theorem
`compiled_request_suffix_current_adjacency` derives their distance from the
existing current-source theorem and the compiler query count. Its premises are
the ordinary `CanonicalPublicPackedDomain` contract and an actual grammar
logical-read budget; it accepts no adjacent probability inequality or
experiment-distance receipt.

For logical-read budget `q`, the exact substituted hidden-patch term is
`hiddenPatchLoss (2*q) = 8*q / 2^256`. This is one concrete current pivot with the
entire compiled future suffix. It is not yet a proof of a single all-request,
whole-lifetime adaptive hybrid family.

## Honest-read and entropy accounting

`literalHonestReads` contains the reads themselves, not only an annotation.
`currentLeafReadBatch` contains exactly `2^23 = 8,388,608` honest reads and
therefore adds `2^24 = 16,777,216` baseline calls after this compiler. The
prepare/record gates remain parameters; matching them to all actual source
leaf addresses and transcript operations is a remaining obligation.

`actual_source_leaf_event_max_mass` specializes the existing original-current
leaf input theorem, retaining the actual full `Q/M` suffix, source coins, joint
masks, salt, leaf index, and uniform fresh 512-bit tape. Its bound is `2^-512`;
the actual source input has not been replaced with a target-independent prefix.

For `R = attempts * 2^23`, the source defines the numerical external adaptive
reprogramming envelope
`R*sqrt(Q_other+R)/2^256 + R*(Q_other+R)/2^513`.
This definition is not an instantiation or proof of a published quantum
adaptive-reprogramming theorem. `Q_other` must include all other honest and
adversarial raw calls in the source transition, while `R` accounts for the
read-after-program calls. This source-transition budget must not be confused
with the separate two-query overhead in the hidden-patch suffix compiler.

## Remaining closure requirements

- Compile measured, adversary-selected proof requests and the complete honest
  current prover into the retained-history coherent schedule, including
  purification or an explicit measurement semantics and padded public aborts.
- Prove actual source address preparation, answer recording, serialization,
  transcript generation, and mask resampling match the grammar gates. Prove
  the source-generated initial state is clean and its gates preserve scratch.
- Specialize generic lookup and retained permutations to the concrete finite
  buffer, including chronological slot freshness and latest-write semantics
  throughout the entire source execution. A fresh slot alone is insufficient:
  increasing-slot/no-future-entry invariants must prevent later occupied slots
  from taking precedence over a newly written lower slot.
- Construct one same-oracle, retained-state, all-request hybrid family. Derive
  each adjacent whole-lifetime bound from this concrete pivot theorem and prove
  its prefix factorization. A generic telescope alone is insufficient.
- Discharge the honest-original to randomized-label source adapter with a
  checked external quantum theorem application and the actual event chronology.
- Complete honest typed-valid witness to canonical packed-domain completeness,
  concrete RNG/hash assumptions, and independent security/release gates.

No full-privacy, PQ128, production authorization, or Rust-verifier refinement
claim follows from this checkpoint. No carrier, runtime, Rust, retained proof
artifact, central import, or shared cache has been changed by this lane.

## Verification record

The coordinator-granted single process passed from `formal/crypto`:

```sh
lake env lean -j1 -M3072 -DwarningAsError=true -DautoImplicit=false HegemonCrypto/SmallWoodV8Smz9CurrentRepeatedPrivacy.lean
```

Thirty roots passed `#print axioms` in the same checked source; the temporary
print commands were then removed. The source SHA-256 is
`902c98043d342aef02fee8d74c693542c474c6367b681d2927e717ea7fae5013`.
Audited roots:
`fresh_record_overrides_previous_lookup`, `fresh_buffer_write_records`,
`history_controlled_fresh_write`, `mutable_query_on_clean_scratch`,
`mutable_query_inverse_preserves_scratch`,
`baseline_scratch_query_is_one_raw_query`,
`baseline_scratch_inverse_is_same_xor_query`,
`mutable_query_is_two_raw_queries`, `halted_mutable_read_is_identity`,
`scratch_preserving_permutation_keeps_clean`,
`mutable_gate_keeps_scratch_clean`, `retained_write_keeps_scratch_clean`,
`compiled_mutable_query_is_physical`,
`safe_request_grammar_preserves_clean_scratch`,
`compiled_grammar_executes_same_physical_program`, `compiled_raw_query_count`,
`run_after_query_list_is_counted_circuit`,
`compiled_grammar_is_current_game_circuit`,
`compiled_request_program_continues_state`,
`compiled_request_program_continues_baseline`,
`literal_honest_read_count`, `current_leaf_batch_has_all_reads`,
`current_leaf_batch_compiler_charges_all_raw_calls`,
`compiled_public_continuation_query_count`,
`compiled_request_stages_preserve_public_abort`,
`compiled_request_stage_query_budget`,
`compiled_request_suffix_current_adjacency`,
`compiled_request_suffix_loss_closed_form`, and
`current_leaf_events_exact`, `actual_source_leaf_event_max_mass`.

Initial checks caught and repaired source/API elaboration issues and unused
section instances; the final check did not require a higher memory limit or
split certificate. No cache/output object was written by this lane. The
coordinator owns shared-cache construction, central imports/inventory,
integration, and commits.
