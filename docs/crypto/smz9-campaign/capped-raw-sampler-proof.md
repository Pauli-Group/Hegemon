# Prove the finite capped raw sampler law


This ExecPlan follows `.agent/PLANS.md` and owns only
`formal/crypto/HegemonCrypto/SmallWoodV8Smz9CappedRawSampler.lean` and this file.

## Purpose / Big Picture


Derive successful field-output uniformity from the same finite raw vector
that produces the explicit exhaustion outcome. This must not import an
uncapped terminating-trace law or assume postselected uniformity.

## Progress


- [x] (2026-09-07 17:21Z) Selected a finite raw-word recursion retaining the `none` atom.
- [x] (2026-09-07 17:24Z) Added the exact finite pushforward and success/abort probability recurrences.
- [x] (2026-09-07 17:28Z) Derived success/abort normalization, conditional uniformity and positive success whenever capacity suffices.
- [x] (2026-09-07 17:36Z) Connected canonical u64 rejection and proved the integer abort count equals the actual finite-vector fiber cardinality.
- [x] (2026-09-07 17:40Z) Strict check passed for same-vector uniform 64-byte blocks via the exact little-endian byte/word bijection.
- [x] (2026-09-07 18:12Z) Strict check passed for the literal counter parser binding, preserving its first accepted prefix and abort outcome, with one compiler capped at 3 GiB and one thread.
- [x] (2026-09-07 20:56Z) Updated the successor maximum request, digest-call cap, candidate capacity and rejection threshold source-only.
- [x] (2026-09-07 20:59Z) Successor counts passed the strict compiler check in the granted single-worker slot.
- [ ] Separate follow-up: derive and evaluate a binomial-tail upper bound from the exact finite count.

## Context and Orientation


The `SmallWoodV8Smz9RawCounterCompiler` module defines literal counter
vectors, raw framing, capped parsing, and exact exhaustion thresholds. DECS
uses 92 blocks or 736 u64 candidates for 700 outputs. A 4150-word request
uses 523 blocks or 4184 candidates, but this is an example, not the general
gamma width. Actual gamma requests `5 * max(830, retained CSR row count)`.
The retained count depends on the public statement. A count bounded by the
20,605 source attempts gives at most 103,025 words, 12,883 blocks and 103,064
candidates. The maximum-size request exhausts at 40 rejections; DECS
exhausts at 37 and the 4150-word example at 35. The Goldilocks modulus is
18446744069414584321; exactly 4294967295 u64 words reject.

## Plan of Work


Use a finite sum of accepted and rejected word types. The first milestone
defines a scanner on an actual fixed-length raw vector, proves its PMF is
the literal iid uniform-vector pushforward, and derives each successful
output's point probability and the separate abort probability recursively.
The second milestone derives successful-output normalization and connects
the word partition to the literal canonical u64 predicate. The final
milestone derives finite counting evidence for exhaustion, retaining the
source's DECS cap and the public-context-dependent gamma cap.

## Concrete Steps


From `formal/crypto`, use the warm cache without shared writes:

    lake env lean -M3072 -j1 -DwarningAsError=true -DautoImplicit=false HegemonCrypto/SmallWoodV8Smz9CappedRawSampler.lean

Successful output is empty with exit code zero. Root owns cache generation,
shared imports, declaration credit and integrated axiom auditing.

## Validation and Acceptance


The same finite raw-vector PMF must produce both uniformly weighted successful
outputs and a separate `none` atom. The exact probability recurrences must
hold for arbitrary finite capacities, including zero capacity and zero
requested outputs. Source counts must calculate DECS 736/37, the 4150-word
example 4184/35, and the gamma maximum 103064/40.
No accepted-proof extraction, compiled Rust execution refinement or
production authority follows from this local sampler law.

## Surprises & Discoveries


The existing infinite terminating-trace construction is not a direct proof
of the capped vector law. The new scanner retains unused finite raw words
and cap exhaustion in one experiment.

The old gamma count omitted retained linear CSR rows. `derive_gamma_prime`
uses the maximum of nonlinear and retained linear constraint counts. This
lane therefore keeps capacity and requested outputs generic and labels
4150/523 strictly as an example. No retained-row maximum is passed off as a
specific statement's actual row count.

The concrete byte-vector-to-list specialization triggered the kernel's
3 GiB memory ceiling even after a generic flattening lemma passed. The
successful refactor keeps the word-vector opaque, transfers a generic list
equality, and rewrites only the named byte-vector coordinate equality.
The whole module then passed within the same 3 GiB, one-thread limit.
The coordinator scheduled checks centrally to avoid duplicate compilers.

## Decision Log


Use a sum type for accepted/rejected u64 words, then prove its exact source
encoding. This avoids assuming field uniformity and keeps the raw proposal
count finite. Use PMF recurrences derived from independent finite-vector
head/tail decomposition, not a caller-supplied probability premise.

## Interfaces and Dependencies


The module imports the frozen raw-counter compiler. `scan` returns an
optional vector of exactly the requested length. `cappedLaw` is its pushforward
of an iid finite uniform raw vector. `successfulPointMass` and `abortMass`
are explicit recurrences derived from that law.

`finite_success_abort_normalization` proves `abort + success = 1`.
`conditional_success_is_uniform` derives the normalized success law; its
nonzero-success condition is itself proved whenever requested outputs do
not exceed candidate capacity. `sourceWordEquiv` maps the accepted/rejected
sum type bijectively onto all u64 words and preserves the exact canonical
predicate. `eightBytesWordEquiv` and `byteBlockWordsEquiv` prove the ordinary
little-endian layout of all 64 bytes. `blockWordsEquiv` is counter-major,
then word-major flattening, with exact coordinate theorems.

`abort_count_is_finite_vector_fiber_cardinality` proves that the integer
recurrence is the cardinality of the real aborting-vector set.
`literal_u64_abort_is_rejection_tail_cardinality` identifies that set with
the exact rejection threshold. `decs_92_block_abort_is_exact_37_rejection_event`
and `example_523_block_abort_is_exact_35_rejection_event` instantiate it.

`exact_literal_byte_counter_parser` identifies the resulting scanner with
the frozen compiler's actual list-of-64-bytes parser, including first-prefix
ordering and `none`. `literal_byte_parser_conditional_output` states the
conditional uniform law directly at that literal parser's list output.

## Idempotence and Recovery


Only the two named new files are edited. No runtime, wallet, retained proof,
shared cache or integration file is modified. Strict Lean checks are
repeatable and read-only without an output path.

## Outcomes & Retrospective


The bounded finite-law milestone through the uniform 64-byte block law passed
strict verification at 17:40Z. The complete module, including the literal
list-parser glue, passed the bounded strict check at 18:12Z. For a fixed uniform vector
of `C` raw words and a request of `n` field elements, the same experiment has
an explicit abort atom and an exactly uniform successful output vector.
If `S(C,n)` denotes the derived success probability and `y` is any output,
the proved law is `Pr[some y] = S(C,n) / p^n`. Conditioning is defined and
uniform whenever `n <= C`; no postselected-uniform premise is supplied.

The exact abort probability is `A(C,n)/(2^64)^C`, where the integer recurrence
is proved equal to the finite aborting-vector count. With `a=p`, `r=2^64-p`,
its boundary conditions are `A(C,0)=0`, `A(0,n+1)=1`, and
`A(C+1,n+1)=r*A(C,n+1)+a*A(C,n)`. Equivalently, for `n<=C`, it counts exactly
the vectors containing at least `C-n+1` rejected words. A kernel-checked
small regression gives `A(3,2)=7` when `a=2,r=1`.

This is an exact probability/counting result, not a numerical upper bound
on that tail. A binomial-tail bound and its source-parameter evaluation are
explicit follow-up work. The input law here is a fixed uniform byte-vector
law. Applying it to a history-selected quantum-oracle query still requires
the compiler/state-restoration argument to justify that game's use; no
adaptive freshness, coherent extraction, compiled Rust equivalence or
production authority is inferred from this sampler theorem.

## Artifacts and Notes


The pre-successor and successor-count checks passed with warning-as-error and
disabled auto-implicit variables. The successor interface was then emitted to
the expected Lake build path for its tail-module dependent.
No `sorry`, admitted axiom, `native_decide` shortcut or desired distribution
premise is introduced. No shared cache, retained artifact or runtime was
modified. The coordinator owns integrated imports and axiom auditing.
The lane uses no scratch build output and stays below its 40 MiB cap.

Revision 2026-09-07 17:24Z: created the finite-law implementation and its
acceptance boundary before verification.

Revision 2026-09-07 17:45Z: completed the checked finite sampler and byte-vector
law and wrote the final parser binding, corrected the source gamma width,
and separated the exact count from a still-unproved numerical binomial-tail
bound.

Revision 2026-09-07 18:12Z: completed strict verification of the whole module
after replacing expensive concrete specialization with opaque generic list
equalities and an explicit coordinate rewrite. Source is frozen for the
coordinator's dependency-cache refresh and integrated axiom audit.

Revision 2026-09-07 20:56Z: updated the successor maximum to 103,025 requested
words, 12,883 digest blocks, 103,064 candidates and threshold 40, without
running Lean ahead of the coordinator's compiler slot.

Revision 2026-09-07 20:59Z: the successor-count source passed its coordinated
strict check, after which its `.olean` interface was refreshed for the tail check.
