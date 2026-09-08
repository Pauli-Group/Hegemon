# SMZ9 honest raw SHA-512 query budget

Source review: 2026-09-07, repaired HGV8RP03 program SHA-512
`180fca50376f7573cacedfb5465a0b4d6bf5c61637152035a682d21038016d2239e2f8b50605f36baa635038348dc984197d6df29347e17e1150c24ff737de84`.

Every attempted invocation of the source-owned SMZ9 engine prover or verifier
uses fewer than `2^26` raw SHA-512 evaluations. The canonical
`compile_and_prove_smallwood_poseidon2_v8_candidate` frontend includes one
prover and two verifiers, so allowing `2^28` evaluations for each attempted
frontend invocation is conservative. Failed requests and repeated verification
must be charged too. These are deterministic source-level call bounds, not
measurements, a Rust execution-refinement theorem, or a SHA-512 security claim.

## Engine call count

The selected backend is `Sha512Poseidon2V8Smz9`, its DECS domain has
`N=2^23` leaves, its opening count is `q=20`, and the tree depth is 23.
The prover follows
`prove_statement_core_with_transcript_backend_profile_and_domain`, including
`pcs_commit`, `piop_run`, the capped opening-nonce loop, and `pcs_open`.
The verifier follows the corresponding core verifier, including
`pcs_recompute_transcript` and `piop_recompute_transcript`.
All function names in this section refer to
`circuits/transaction/src/smallwood_engine.rs`.

| Raw digest or field-XOF site | Prover cap | Verifier cap |
| --- | ---: | ---: |
| Strict leaf commitments | `N` digests | `q` digests |
| Internal Merkle nodes | `N-1` digests | `q*23` digests |
| Statement-bound Merkle root | 2 digests | 1 digest |
| PIOP input digest | 1 digest | 1 digest |
| Complete PIOP transcript digest | 1 digest | 1 digest |
| DECS opening transcript digest | 1 digest | 1 digest |
| DECS coefficient matrix | 1 field-XOF | 1 field-XOF |
| PIOP coefficient matrix | 1 field-XOF | 1 field-XOF |
| PIOP opening points: nonce selection and final replay | 17 field-XOFs | 17 field-XOFs |
| Fixed DECS query sampler | 1 field-XOF | 1 field-XOF |

There are two root digests in the prover: `decs_commit` derives the challenge
after constructing the tree, and `pcs_commit_transcript_words` independently
reconstructs the same root binding. Repeating an input still counts as a raw
oracle evaluation. The verifier's Merkle routine also recomputes shared parents:
`decs_recompute_root` retains all 20 lanes through all 23 levels. Its raw-work
bound is 460 internal calls, not the 372-node compact serialization bound.

`choose_opening_nonce_for_profile` performs at most 16 attempts under this
backend. Successful prover and verifier paths each replay the selected opening
request once. `xof_decs_opening` dispatches directly to
`xof_decs_opening_fixed_no_grinding`; the unrelated legacy unbounded sampler is
not selected. `decs_open` copies retained paths and tape bytes without hashing
the full tree again. Profile binding words are decoded without extra SHA-512
calls in `transcript_binding_words_for_domain` for SMZ9.

Every digest-table entry is one complete raw SHA-512 evaluation. In particular,
`transcript_xof_digest` dispatches directly to a single counter-zero digest for
SMZ9; it does not invoke rejection sampling. The strict leaf fast path likewise
executes one complete digest per leaf. Its input length affects SHA-512 work,
but not the number of complete-function oracle queries in this model.

## Field-XOF exhaustion is charged

For a nonzero output request of `n<=2^24` words,
`smallwood_sha512_field_xof_digest_call_cap_v1` returns

```text
C(n) = ceil((n+32)/8) <= 2^21+4.
```

The block-reading loop checks this cap before each raw digest. Zero-length and
over-cap requests make no raw query. Exhaustion after the cap returns an error;
the surrounding failure scope may continue with deterministic poison values,
but it does not restart the invocation or remove any previously spent queries.
The same static 20-call bound covers that continuation.

The optional `raw_digest_calls` transcript record is **not** the proof of this
bound. Currently `transcript_xof_words` records zero when the fallible reader
exhausts, although the reader has already made capped raw digest calls. Summing
successful trace counters alone would therefore undercount failed requests.
The budget here instead charges the full syntactic cap for every reached
field-XOF site, including failed and repeated ones.

The resulting conservative engine bounds are

```text
H_prover   <= 2*N+4 + 20*(2^21+4) = 58,720,340 < 2^26,
H_verifier <= q*(23+1)+4 + 20*(2^21+4) = 41,943,604 < 2^26.
```

Neither success, acceptance, field-XOF uniformity, fresh coins, nor a
cryptographic assumption is needed for these count inequalities. Allocation or
other early errors reduce the count. The bounds concern the exact source-owned
adapter and selected SMZ9 profile; an arbitrary third-party implementation of a
Rust adapter trait is not covered merely because it has the same method names.

## Frontend and lifetime composition

The research interpreter now has a tighter kernel-checked count for its actual
chronological prefix through `h_piop`, in
`formal/crypto/HegemonCrypto/SmallWoodV8Smz9SourceQueryBudget.lean`:

```text
N + (N-1) + C(700) + C(5*20605) + 4 = 16,790,194.
```

The four single-digest reads are the two statement-bound root reads, PIOP input
digest, and final PIOP digest. The proof uses the actual symbolic Merkle-tree
recursion and counts exhausted XOF branches. Its full continuation contributes
an additional explicit worst-branch query bound. Applying the honest-future
compiler retains exactly the future's query count while removing its selected
programming events, leaving at most `N` selected leaf events for this request.
The corresponding leaf-reprogramming theorem applies the existing external
adaptive-reprogramming premise with these derived counts. This tighter prefix
count excludes the later opening/serialization schedule; it neither replaces
the complete-engine bounds above nor establishes Rust execution refinement.

`SmallWoodV8Smz9PostFinalQueryBudget.lean` now supplies that remaining modeled
schedule: at most `85` nonce-selection/replay reads plus `12` DECS
opening-hash/index reads, for `97` post-final reads. Its concrete
`sourceCompleteByteRequest` passes the actual computed challenges, responses,
transcript, digest, pending-error flag, source tree and original leaf tapes to
the source byte constructor. The full modeled request therefore costs at most
`16,790,291 + Q_future`, and selects at most `8,388,608 + R_future` leaf events.
The future bounds quantify over every proof/error output. Both modules passed
strict checking, independent read-only review and the 603-root integrated gate.
The program begins with supplied field coins/masks; operating-system entropy
failures and Rust statement-binding serialization are not proved by these
syntactic counts.

`circuits/transaction/src/smallwood_poseidon2_v8_frontend.rs` calls the engine
prover once in `prove_smallwood_poseidon2_v8_candidate`, then immediately checks
the result with the existing relation. Its public canonical compiler wrapper
also calls the source-factory verifier once. Thus a successful compile-and-prove
call contains one prover and two verifier invocations; any failure follows a
prefix of these calls. The fixed program-integrity initializer in
`smallwood_poseidon2_v8_program_digest_matches` performs at most two additional
SHA-512 evaluations per process. Charging both on every frontend invocation
is an overestimate. The plain frontend's relation arithmetic uses Poseidon2,
not additional SHA-512 transcript queries.

Consequently

```text
H_frontend <= H_prover + 2*H_verifier + 2
           = 142,607,550 < 2^28.
```

Let `T` count all attempted canonical compile-and-prove requests **plus** all
additional engine/verifier invocations outside those requests. Retried,
abandoned, rejected, orphaned, and repeated calls are included, even if they
return no proof or repeat a previously queried input. Let `H_other` count any
other use of the same ideal raw oracle, including wallet key derivation,
diagnostic/report generation, unrelated trusted services, and oracle-dependent
setup outside the plain frontend. Then a valid conservative exposure budget is

```text
E = Q_adversary + H_honest + H_other,
H_honest <= 2^28*T.
```

This is a usable deterministic input to the privacy hybrid's lifetime budget.
It does not compile Rust into that hybrid or establish the entropy/reprogramming
steps. For example, `Q_adversary<=2^64`, `T<=2^21`, and `H_other<=2^63` imply
`E<2^65`. This is an explicitly conditional parameter example, not a deployed
query limit or production security authorization. A simulator or proof reduction
that makes additional queries must establish its own cap and charge them; these
are not silently included by calling them honest work.

## Exact arithmetic check

The following needs only Python's integer arithmetic:

```python
N, q, depth = 2**23, 20, 23
xof_cap = (2**24 + 32 + 7)//8
assert xof_cap == 2**21 + 4
prover = 2*N + 4 + 20*xof_cap
verifier = q*(depth+1) + 4 + 20*xof_cap
frontend = prover + 2*verifier + 2
assert (prover, verifier, frontend) == (58720340, 41943604, 142607550)
assert prover < 2**26 and verifier < 2**26 and frontend < 2**28
assert 2**64 + 2**28*2**21 + 2**63 < 2**65
```

The loop and call-graph evidence must be rechecked after changes to the named
source functions. No measured successful trace, retained artifact, or passing
finite test is substituted for that evidence.
