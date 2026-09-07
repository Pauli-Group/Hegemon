# Compile literal raw-counter queries into vector queries


This ExecPlan is maintained under `.agent/PLANS.md`. It owns only the new
`formal/crypto/HegemonCrypto/SmallWoodV8Smz9RawCounterCompiler.lean` module and
this document. The surrounding security campaign and release gates remain
unchanged.

## Purpose / Big Picture


The finite counter compiler groups SHA-512 outputs by their literal input-byte
prefix before the final eight-byte counter. A logical answer is the complete
vector of raw 512-bit blocks, not a field challenge and not a bare Merkle root.
The user can check that two coherent vector-oracle calls exactly simulate each
raw query while preserving every unselected raw input and private workspace.
This is a necessary local bridge, not an accepted-proof extractor or a claim
that the end-to-end SMZ9 argument has reached 128-bit security.

## Progress


- [x] (2026-09-07 16:52Z) Read source framing, capped parser and existing physical-query primitives.
- [x] (2026-09-07 16:55Z) Added framing, full-domain factorization and physical simulation declarations.
- [x] (2026-09-07 17:00Z) Strict compiler check passed for the initial physical compiler.
- [x] (2026-09-07 17:06Z) Added same-vector capped parsing, success/abort equivalences and exact rejection thresholds.
- [x] (2026-09-07 17:13Z) Strict compiler check passed for padded full-domain simulation, uniform-law transport, typed framing injectivity and concrete parser regressions.
- [x] (2026-09-07 17:16Z) Final executable suffix-routing check and evidence handoff completed.
- [ ] Separate follow-up: prove finite-cap conditional field-output uniformity on this same vector; it is not assumed here.

## Context and Orientation


`circuits/transaction/src/smallwood_engine.rs` defines the raw preimage as an
optional profile length and profile, role length and role, word count and
little-endian words, followed by a little-endian u64 counter. The active SMZ9
profile is present and has 53 bytes. The existing
`SmallWoodV8Smz9WholeViewObservation` module supplies those exact profile bytes
and the source-shaped key. `SmallWoodV8Smz9HiddenLeafQrom` supplies finite
complex-amplitude states, XOR-register conventions and squared Hilbert norm.
A coherent oracle query is a reversible transformation of all computational
basis states, extended linearly to their complex amplitudes.

DECS requests 700 field words and permits 92 full digest blocks. PIOP gamma
requests `5 * max(830, retainedLinearRows)` words, not `5 * 830` in general.
The 15,561 nonempty raw-replication rows already exceed 830; the complete
program has at most 20,569 CSR attempts. The resulting gamma request lies
between 77,805 and 102,845 words and its cap between 9,730 and 12,860 blocks,
subject to the retained-row bounds. Each block supplies eight u64 proposals.
Only words strictly below the Goldilocks modulus are accepted. Exhaustion is
an explicit error, so a finite vector must not be replaced by an unconditional
uniform field-output value without proving the corresponding abort law.

## Plan of Work


First prove that literal framed prefix/counter pairs encode injectively and
that the source frame parser returns its role, payload and counter. Then
partition the entire raw domain into selected counter pairs and their exact
complement. A bijection of complete oracle tables transports the finite
uniform law to a product of the vector and complement tables. Finally define
compute, controlled counter selection and uncompute as basis equivalences,
extend them linearly, and prove norm preservation and equality on the complete
clean-ancilla subspace. The auxiliary vector must return to zero.

The split-table stage keeps an explicit complement table. The stronger padded
stage gives every complement input its own vector address and a fixed selected
counter. It therefore simulates every raw query with two calls to one common
vector oracle, without treating an unknown complement oracle as free stored
data. Unused vector coordinates are independent random padding.

## Concrete Steps


From `formal/crypto`, reuse the already warm dependency cache and run:

    lake env lean -DwarningAsError=true -DautoImplicit=false HegemonCrypto/SmallWoodV8Smz9RawCounterCompiler.lean

No node, wallet, runtime build, dependency download or retained artifact rewrite
is required. The expected successful compiler output is empty with exit code 0.
The coordinator owns shared imports and declaration-credit integration.

## Validation and Acceptance


Acceptance requires literal source-key equality, injective counter framing,
source-frame roundtrip, exact complement preservation, a uniform-table product
law derived from a bijection, a norm-preserving two-query linear operator, and
exact clean-register simulation for arbitrary private workspace. The concrete
cap theorem must compute 92/736 for DECS and use the actual retained CSR count
for gamma. The 4150-word/523-block case is only a parser regression example.
Compilation alone is not acceptance-to-extraction or production refinement.

The regressions also require an all-`ff` 64-byte block to abort a one-word
request, an all-zero block to supply eight zero words, zero requested words
to return an empty output, and the exact field modulus to reject rather than
being reduced modulo the field.

## Surprises & Discoveries


The compact SMZ9 authentication paths omit intermediate hashes. The
oracle-free full-path input needed by the coherent Merkle extraction theorem
therefore requires an explicit classical verifier-trace expansion. Its raw
hash calls must be charged in the verifier budget; compact proof bytes alone
do not already contain those full paths.

A complement table may be mathematically fixed without being efficiently
available to a reduction. Padded addresses remove that resource ambiguity:
the same vector oracle answers selected counter inputs and every complement
input. Its exact raw-oracle law follows from injective coordinate restriction.

## Decision Log


Use raw byte prefixes as logical vector inputs. This proves counter-block
independence without assuming a typed-key-to-digest collision property, and
keeps all profile/role/word-count/payload bytes. Preserve the entire complement
as its own oracle table. Do not interpret a root-wrapper digest or PIOP-input
digest as a bare Merkle root. These decisions were made on 2026-09-07.

Use `twoRoutedVectorQueryLinearEquiv` with `fullRawPaddedCoordinate` for the
single-oracle query count. Retain the split-table construction as a useful
factorization. Keep finite-cap field uniformity separate from the already
proved uncapped terminating-trace law, which does not automatically certify
this vector's abort-conditioned distribution.

## Interfaces and Dependencies


The new module depends only on already compiled hidden-leaf and whole-view
modules plus Mathlib equivalences. Its central public declarations are
`rawTableFactorization`, `uniform_raw_table_factorization`,
`padded_vector_oracle_has_exact_uniform_raw_law`,
`two_routed_queries_preserve_squared_hilbert_norm`, and
`two_routed_vector_queries_coherent_simulation`. The finite-table distribution theorem
is stated for finite raw-query universes; the domain bijection itself also
retains the complement in the complete list-of-bytes domain.

`typed_source_counter_frame_injective` proves role/u64-word/counter tuple
injectivity through the literal parser under representable length bounds.
It does not give this claim to arbitrary unbounded natural-number words.
`raw_counter_suffix_roundtrip` supplies executable prefix/counter routing
without a hash preimage search.

`uniform_vector_block_point_mass` proves that any selected raw block has
point mass `2^-512`; using the cardinality of the entire vector as that
denominator would be incorrect. A common width of 12,860 can cover the two
field stages under the program's 20,569-row upper bound: DECS reads its first
92 blocks, gamma uses its statement-derived cap, and core hashes select
counter zero. Other counters and raw inputs remain in the complement. The
generic two-query compiler is independent of the selected vector width.

## Idempotence and Recovery


The Lean check is read-only when no output path is supplied and may be repeated.
Only the two named new files belong to this lane. Existing working-tree edits,
shared caches and retained proof artifacts must not be reverted or overwritten.

## Outcomes & Retrospective


The bounded compiler milestone is complete. It proves byte and typed framing
injectivity; source and suffix parser roundtrips; full-domain factorization;
finite uniform-table product and restriction laws; two-query reversible and
complex-linear simulation with clean auxiliary restoration; and same-vector
capped parsing including success length, abort and rejection-count equivalence.
A 700-word request aborts exactly when at least 37 of its 736 candidates
reject; a 4150-word request aborts exactly when at least 35 of 4184 reject.
The latter is not the full current gamma request. The source uses
`derive_gamma_prime`'s maximum of nonlinear and retained linear counts;
`gamma_caps_of_retained_row_bounds` proves the corrected cap interval from
the explicit retained-count hypotheses.

The optional probability step remains open: for each successful output `y`,
prove directly on the same uniform raw vector that
`Pr[parse(vector) = some y] = Pr[success] / p^requested`.
No declaration assumes or claims it. A finite-word probability argument is
also still needed to derive the binomial rejection-tail upper bound from
the deterministic threshold established here.

The physical XOR response is `Fin 512 → ZMod 2`; the literal field parser
uses the source-shaped 64-byte digest. Their canonical bit/byte packing
adaptation is a separate interface, not proved by arbitrary-cardinality
identification here. Complete bit-operation cost bounds, finite-universe
instantiation for an arbitrary bounded adversary, coherent Merkle substitution,
state-restoration composition, full verifier query accounting and compiled
Rust execution refinement remain separate. This compiler is not production
authority.

## Artifacts and Notes


The strict Lean command above completed with exit code zero and no warnings.
No `sorry`, admitted axiom, native-decider shortcut or assumed extraction
success was introduced. The literal all-`ff` abort and other parser regressions
are kernel-checked theorem bodies. Shared imports, declaration credit and
integrated axiom auditing belong to the coordinator; no shared cache or
retained artifact was rewritten here.

Revision 2026-09-07: created the bounded implementation plan and its exact
evidence boundary before verification.

Revision 2026-09-07 17:16Z: completed the literal compiler; added padded
complement routing after finding the fixed-table efficiency ambiguity;
recorded exact finite-cap and composition residuals.

Coordinator correction 2026-09-07: source CSR binding exposed the earlier
gamma undercount. Renamed the 4150-word facts as examples, recorded the actual
maximum-count rule and proved its conditional 9,730–12,860 cap interval.
