# HX512 SmallWood verifier Fiat--Shamir schedule audit

Date: 2026-08-22  
Scope: source-only audit of `smallwood_engine.rs` and
`smallwood_hx512_transcript.rs`; no Cargo build, proof generation, benchmark,
or production authorization was run.  This report is not a security proof or a
release artifact.

## Verdict

The theorem-faithful minimum fresh-core prefix is:

```text
raw_decs_root[64] || h3_piop_input[64] || h5_piop_transcript[64]
```

`h5` is the existing `h_piop` field.  Relative to the prior fresh layout that
already carried `h5`, the exact delta is **+128 inner bytes and +128 outer-wire
bytes**.  The fixed HX512 outer framing overhead is unchanged; a future
transport envelope outside this codec must be measured separately.

The complete canonical fresh core is ordered as follows:

```text
raw_decs_root[64]
|| h3_piop_input[64]
|| h5_piop_transcript[64]
|| ppol_highs
|| plin_highs
|| rcombi_tails
|| subset_evals
|| partial_evals
|| compact_authentication_paths
|| q independent_leaf_tapes[72]
|| masking_evals
|| decs_high_coeffs
|| opened_row_scalars
```

Each response matrix has exact profile-owned dimensions and is encoded with
`u32_be rows || u32_be columns || canonical u64_be cells`.  Authentication
paths have exact count `q` and explicit canonical per-path lengths bounded by
the 20-level tree (compact paths need not all contain 20 nodes); the 72-byte
tapes are fixed-width.  The inner core carries neither a salt nor a grinding
nonce: the outer wire owns the sole 64-byte salt and HX512 has no grinding
nonce.

This prefix is sufficient only with the exact eight-event verifier described
below.  It is not sufficient if either deferred digest is trusted, checked
under a later chain state, or checked in a different order.  A raw DECS root,
not `h1`, is the canonical first value: the root is the PCS commitment required
before the event-1 challenge, and event 0 computes `h1` from its exact framed
message.  Carrying `h1` instead is the same byte width but changes the theorem's
commitment/message surface and would require a new proof.

This is a structural dependency and byte-minimality result only.  The q48/s6
parameters used to instantiate the graph are **not security-authorized**.  A
parallel composed-soundness audit found that the cited epsilon-1 paper term
`C(N,d+2)/|F|^eta` caps at one for this profile, while the engine's bare
`|F|^-eta` term is an unproved custom strengthening.  Consequently no
soundness, PQ128, QROM, engine-authorization, or production flag may be inferred
from the schedule or the +128-byte result.

At the audit checkpoint, production remains fail-closed.  The transcript owns
a sound deferred-check API and prefix-mutation tests, but the shared engine was
still being integrated.  This audit found and routed a source mismatch:

```text
event-1 field sample count = eta * LVCS_rows
```

The engine passes `cfg.nb_lvcs_rows` to `derive_decs_challenge`; the audited
transcript initially used `eta * core.polynomial_count`.  Since
`polynomial_count = R + 2*rho` while `LVCS_rows = (K+s)*beta`, that revision
could not execute the engine schedule.  It was repaired to `eta*LVCS_rows` in
the quiescent transcript SHA-512 recorded by `source-snapshot.json`; a sibling
source audit found no remaining in-module schedule defect and the root agent
independently ran its nine isolated tests successfully.  This agent did not run
Cargo or that binary.  Engine prefix/parser/verifier integration remains a
separate freeze condition.

The non-quiescent engine source observed during this audit did contain the
required structural closure: transcript-context installation and its guard
were private; the only crate-visible HX512 core seams were atomic prove/verify
functions; the fresh outer wrapper imported those atomic seams; and verifier
success executed generic core verification followed by mandatory
`guard.finish()?`.  The traced verifier order was event 6, event 7, reconstructed
root, reconstructed `M3`/h3, reconstructed `M5`/h5, then terminal finish.  This
is not promoted to frozen evidence because the engine owner had not handed off
a quiescent hash, and no engine test was run by this source-only audit.

## Binding before event zero

Let `B` be the statement-binding SHA-512 digest.  Its canonical preimage binds:

1. the candidate binding-frame domain;
2. the caller-owned identity header;
3. the maximum inner-proof byte cap as `u64_be`;
4. the exact 983-byte external statement;
5. the exact 136-byte verifier context (stable root, `u64_le` parent height,
   expected action intent);
6. the sole outer-owned 64-byte salt; and
7. the exact 422-byte geometry/profile descriptor, including relation,
   topology, and eight-event schedule digests.

The initial transcript chain is `c0 = B`.  Every scheduled request additionally
binds its unique role domain, request kind, `u64_be` event index, prior chain,
descriptor, and canonical message.  Merkle leaf/node history hashes are
statement-bound but chain-independent; they do not add transcript events.

## Exact eight-event verifier program

Notation: `H` is the scheduled SHA-512 request, `XOF_f` is the unbiased
Goldilocks sampler, `XOF_i` is the sorted-distinct index sampler, `q=48`,
`eta=5`, `rho=5`, `s=6`, `N=2^20`, `L=nb_lvcs_cols`, and
`P=nb_polys=R+2*rho`.  `BE_words(x)` parses each eight-byte digest chunk as
`u64_be`; the canonical field-message encoder is
`u64_be(word_count) || each_word_u64_be`.  Consequently, digest bytes survive
the digest-to-words-to-message round trip unchanged.

| Event | Exact operation | Proof-carried dependency | Earliest verifier action |
|---:|---|---|---|
| 0 | `h1 = H(root_role, B, 0, c0, root_message)` | `raw_decs_root[64]`; salt and `N` are already bound/derived | Execute immediately. `root_message = N_u32_be || 64_u16_be || salt64 || 64_u16_be || raw_root64` (136 bytes). |
| 1 | `(eta * LVCS_rows)` unbiased field samples, terminal chain `h2` | none beyond `h1` and bound geometry | Execute immediately after event 0. The descriptor binds stage, count, and Goldilocks modulus. |
| 2 | `h3 = H(piop_input_role, B, 2, h2, M3)` | claimed `h3[64]` | Provisionally advance on the prefix claim and retain the immutable `(B,event=2,prior=h2,role,kind)` snapshot. `M3` cannot yet be reconstructed. |
| 3 | `rho * max(nonlinear_constraints, linear_constraints)` field samples, terminal chain `h4` | none beyond claimed `h3` and geometry | Execute immediately after accepting the event-2 claim. |
| 4 | `h5 = H(piop_transcript_role, B, 4, h4, M5)` | existing `h_piop[64]` | Provisionally advance on the prefix claim and retain the immutable event-4 snapshot. `M5` cannot yet be reconstructed. |
| 5 | `s=6` unbiased field openings, terminal chain `h6` | none beyond claimed `h5` and geometry | Execute immediately. These six points enable reconstruction of combination heads and the PIOP low coefficients. |
| 6 | `h7 = H(decs_opening_role, B, 6, h6, M7)` | no digest claim; uses `h5`, proof `rcombi_tails`, `partial_evals`, and opened `row_scalars` | Reconstruct combination heads after event 5, construct `M7` exactly, and execute the real SHA-512 event. |
| 7 | `q=48` unbiased sorted-distinct indexes in `[0,N)`, terminal chain `h8` | none beyond `h7` and geometry | Execute immediately after event 6. `finish` returns `h8`; it issues no ninth oracle request. |

Canonical scheduled absorb messages are:

```text
M3_words = BE_words(h1)
           || dec_poly[0] coefficients constant-term-first
           || ...
           || dec_poly[eta-1] coefficients constant-term-first

M5_words = BE_words(h3)
           || for rep in 0..rho:
                full out_ppol[rep]
                || out_plin[rep][1..]

M7_words = BE_words(h5)
           || for combination in 0..(beta*s):
                combi_head[combination]
                || rcombi_tail[combination]

M{3,5,7} = u64_be(word_count) || each word as u64_be
```

For HX512, legacy public binding words are empty because `B` already binds the
statement and verifier context.  Adding them again would be a different
transcript.

## Why the deferred values are necessary and sufficient

### Raw root, not `h1`

The root is the early DECS commitment and is not derivable from the statement
or any proof prefix other than itself.  It can only be reconstructed after
event 7 reveals the 48 authenticated leaf indexes.  Sending the raw root lets
the verifier execute event 0 exactly and later compare the reconstructed root
byte-for-byte.  No deferred event-0 digest is needed.

### `h3` is necessary

The proof carries `high_coeffs[k] = dec_poly[k][q..]`.  The missing low part is
exactly `eta*q = 5*48 = 240` canonical field words.  Those low coefficients are
recovered by polynomial restoration from evaluations at the event-7-selected
points, so `M3` is unavailable before event 3.  Carrying those missing words
would cost `240*8 = 1,920` bytes.  A 64-byte `h3` claim is 1,856 bytes smaller
and preserves the same logical event once its exact preimage is checked.

### Existing `h5` is necessary

`M5` contains the full PIOP output polynomials.  The proof carries only their
high coefficients; their low coefficients are reconstructed at the six
event-5 opening points from the opened row scalars.  The verifier therefore
needs the already-carried 64-byte `h5` to obtain event 5.  Removing it creates a
challenge/preimage cycle.

### No `h7` claim is needed

After event 5, `pcs_reconstruct_combi_heads` derives every combination head
from the six opening points, row scalars, and partial evaluations.  Appending
the already-carried matching recombination tails to `BE_words(h5)` gives `M7`
before event 7.  Carrying `h7` would add 64 bytes without breaking any remaining
dependency.

The sampler-produced `h2`, `h4`, `h6`, and terminal `h8` are deterministic
from prior chain plus bound descriptors and need not be serialized.

## Deferred verification after event 7

The acceptance-preserving post-event-7 order is strict:

1. derive the 48 DECS algebraic points and reconstruct the authenticated rows;
2. reconstruct the Merkle root from leaves, independent 72-byte tapes,
   masking evaluations, and compact authentication paths; compare it with
   `raw_decs_root`;
3. use the already-derived event-1 coefficients, opened evaluations, masking
   evaluations, and high coefficients to restore the five full DECS
   polynomials; encode exact `M3`; recompute event 2 from its saved snapshot and
   compare with claimed `h3`;
4. reconstruct the full PIOP polynomials; encode exact `M5`; recompute event 4
   from its saved snapshot and compare with existing `h5`; and
5. call terminal `finish`, which must reject unless all three checks completed.

Recomputing event 2 or 4 physically after event 7 is theorem-faithful because
the hash is evaluated against the immutable original request snapshot and the
same canonical message.  It is an evaluation-order optimization of the same
deterministic verifier predicate, not a new transcript event.  The claimed
digests occur in the proof prefix before any response derived from them.

This argument is conditional on an implementation-refinement proof showing
that the eager and deferred accept predicates are identical.  It does not by
itself establish PCS/IOP soundness, complete ZK, or composed QROM security.

## Designs rejected by this audit

- Starting at event 5 from `h5` without logically executing/claiming events
  0--4 is out of order.
- Trusting `h3` or `h5`, or checking either under the terminal/current chain
  instead of its saved prior-chain snapshot, gives the prover a free oracle
  output and is unsound.
- Checking `h5` before exact `h3`, or allowing `finish` with any unresolved
  claim, is not the same verifier predicate.
- Carrying `h1` but omitting the canonical raw DECS commitment changes the PCS
  transcript/theorem surface.
- Carrying `h7` is non-minimal because its message is already available before
  event 7.
- Encoding digest chunks little-endian and then words big-endian silently
  byte-swaps each eight-byte chunk and changes `M3`, `M5`, and `M7`.
- Replacing any canonical message with a host digest, reordered matrix, or
  different framing to reduce bytes changes the Fiat--Shamir protocol and
  requires a new theorem and release identity.

## Mutation-safety requirements

The fixed production verifier must propagate every transcript error and test:

- every byte of raw root, `h3`, and `h5`;
- prefix swap, omission, truncation, duplication, and trailing bytes;
- field-message count, byte order, word order, and digest raw-byte round trip;
- every bound statement/context/salt/profile/identity/cap byte;
- stage role, request kind, event index, and prior-chain changes;
- matrices, compact paths, every opened 72-byte tape, masking values, high
  coefficients, and row scalars;
- early, duplicate, and out-of-order calls; and
- terminal parity between eager prover execution and deferred verifier
  execution, with an explicit unresolved-claim rejection.

The current API returns errors for out-of-order calls but is not a compile-time
typestate proof: a caller can ignore a recoverable `Err`.  This is not a proof
mutation vulnerability in a fixed verifier that uses `?` on every call, but a
production entrypoint/refinement test must establish that no error is ignored.

The engine adapter has an additional fail-closed obligation.  Its legacy
non-`Result` hash hooks can record a replay failure and return a zero fallback
so the generic algebraic reconstruction can unwind later.  Only the HX512
context guard's terminal `finish()` reports that recorded failure and rejects
unconsumed cached challenges.  The authorized entrypoint must therefore be one
atomic path equivalent to:

```text
guard = enter_exact_deferred_context(prefix)
verify_core(...)?
guard.finish()?        // required before returning success
```

Dropping/clearing the guard after a nominal `verify_core` result is not an
acceptable verifier.  No release route may invoke the generic core directly or
ignore terminal `finish`.

## Fail-closed release gates

This source audit cannot authorize production.  Keep admission false until all
of the following are simultaneously retained and independently checked:

- engine event-1 count is exactly `eta*LVCS_rows` and matches the profile;
- fresh parser/serializer uses the exact 192-byte prefix and rejects all other
  orderings and lengths;
- the engine verifier uses the deferred driver and completes root -> `M3` ->
  `M5` checks before accepting;
- raw digest bytes round-trip through the canonical BE word encoding;
- full prove/verify and exhaustive mutation tests pass from a clean source
  snapshot;
- Rust-verifier/eager-deferred refinement is discharged;
- complete ZK and composed >=128-bit PQ/QROM accounting are discharged; and
- the epsilon-1 bound is derived from an applicable theorem without replacing
  its capped combinatorial term by an unproved `|F|^-eta` strengthening; and
- the exact identity, wire cap, relation/topology/transcript digests, artifact,
  restart/reorg checks, and release manifest are bound.

See `dependency.mmd`, `wire-delta.json`, and `source-snapshot.json` in this
directory for the compact graph, byte arithmetic, and frozen-source status.
