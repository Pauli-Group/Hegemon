# Close the independent SmallWood production proof path

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`,
`Decision Log`, and `Outcomes & Retrospective` must be kept current while work proceeds.
Maintain this document in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

Hegemon must accept private transactions using independent SmallWood proofs without the retired
recursive block artifact. The production claim is allowed only when the exact proof bytes accepted
by Rust are connected to the exact Hegemon transaction relation and block supply theorem in Lean,
the remaining computational assumptions are reduced to explicitly named properties of the deployed
hash construction, and measured proof size, proving latency, verification latency, and block
admission throughput meet the chain's operational requirements.

This plan deliberately separates a valid cryptographic proof from a release label. If the
post-quantum reduction or an implementation-refinement step remains a hypothesis, the code may be
useful research but the release gate must say `no-ship`; it must not call the result production
ready.

## Progress

- [x] (2026-07-28 18:26Z) Audited the active branch, Rust proof profile, Lean soundness modules,
  active block policy, formal claim ledger, and current production documentation.
- [x] (2026-07-28 18:26Z) Identified that
  `formal/lean/Hegemon/Consensus/AcceptedSmallWoodBlockComposition.lean` still proves a block with
  a retired `CanonicalProvenBatchBinding`, while active Rust policy accepts independent transaction
  proofs and rejects new recursive candidates.
- [x] (2026-07-28 18:26Z) Identified that the active 32-byte Merkle and transcript digest cannot
  supply 128 bits of generic quantum collision work; a Level-5-equivalent hash-binding target needs
  at least 384 effective output bits and practical margin.
- [x] (2026-07-29 02:48Z) Replaced the active Lean block model, theorem, vectors, claim ledger, and
  blueprint dependency with direct ordered composition of independently verified transaction
  proofs. The corrected theorem and vector generator compile.
- [x] (2026-07-30 03:18Z) Remove experimental recursive/aggregation fixtures that do not contribute to the independent
  transaction proof and preserve only reusable measurement, parser, sampling, transcript, and
  verifier-refinement work.
- [x] (2026-07-29 03:34Z) Measured the current V3 release implementation: 104,527 exact wire bytes,
  approximately 3.57 seconds warm proving, 13.47 milliseconds warm verification, 74.24 sequential
  proofs/second verification throughput, and approximately 762 MiB peak RSS including the test
  process. The 1,000,000-weight block limit admits at most nine such proofs before ciphertext and
  other transaction bytes.
- [x] (2026-07-30 03:18Z) Define one exact post-quantum attack-cost model and a conservative Level-5-equivalent
  acceptance predicate for every binding, transcript, and interactive-soundness term.
- [x] (2026-07-30 03:18Z) Replace the 256-bit commitment/transcript digest with a versioned hash construction whose
  collision, preimage, XOF, and domain-separation properties meet that predicate; bind its exact
  byte grammar in Lean and Rust.
- [x] (2026-07-30 03:18Z) Search and benchmark the proof-parameter Pareto frontier under the hard security predicate,
  minimizing proof bytes first while requiring practical proving and verification latency.
- [x] (2026-07-29 05:12Z) Implemented the checked compressed production relation: 699 packed rows,
  890 nonlinear constraints, dense 61-bit range reconstruction, and Poseidon2 boundary/S-box-wire
  reconstruction. Honest witnesses pass and mutations of a range digit, S-box wire, or final
  Poseidon boundary reject.
- [x] (2026-07-29 05:15Z) Generated and verified the exact practical Level-5-width candidate:
  117,806 wrapped bytes, 2.861 seconds proving, 7.754 milliseconds verification, 1.43 GB peak RSS,
  and a 262.38-bit interactive floor under the pinned 1,048,576-point, 23-query profile.
- [x] (2026-07-29 07:22Z) Transcribed the current SmallWood straight-line extractor structure and
  the concrete CMS compressed-oracle lemmas from their primary papers. Confirmed that the active
  four logical challenge outputs contain `5, 36, 5, 8` Goldilocks words; the last eight words
  canonically encode 23 distinct DECS indexes.
- [x] (2026-07-29 16:42Z) Corrected the DECS polynomial-binding term to the published SmallWood
  Theorem 1 expression `binomial(N, d_decs + 2) * epsilon_D`. The previous
  `(N / d^beta + 2) * (n_rows / |F|)^eta` expression is not the theorem proved by SmallWood or its
  DECS precursor and cannot authorize production.
- [x] (2026-07-29 17:08Z) Implemented the exact integer corrected term in Rust, added a uniform
  `eta x n` DECS challenge for the Level-5 format, and searched the corrected parameter frontier.
  The practical one-million-point candidate is 184,747 exact wrapped bytes, 9.058 seconds traced
  proving, 13.727 milliseconds verification, and 262.718 bits of four-term interactive error.
- [x] (2026-07-30 02:31Z) Proved the deterministic DECS extraction algebra: zero Lagrange
  residual is equivalent to a degree-bounded interpolation on a fixed support, every invalid
  committed word has a nonzero `d + 2` support witness, and every accepted affine masked
  combination lies in the exact finite uniform-matrix failure event. The active theorem
  instantiates `N = 2^20`, `d = 126`, `n = 483`, and `eta = 33` and yields the checked
  `binomial(2^20, 128) / |Goldilocks|^33` term.
- [x] (2026-07-29 10:14Z) Corrected the Lean LVCS inverse to match production Rust: the 107
  stacked data cells are evaluations at points `20 .. 126` after rotating
  `[107 data | 20 hiding]` to `[20 hiding | 107 data]`; they are not coefficients at those
  degrees. Rebuilt the complete dependent `HegemonCrypto` library after the correction.
- [x] (2026-07-29 10:14Z) Proved exact DECS `poly_restore` uniqueness from 20 distinct evaluations
  and the transmitted coefficients in degrees `20 .. 126`. Proved that a false LVCS combination
  of extracted degree-126 rows yields a nonzero degree-126 discrepancy with the exact
  `choose(126, 20) / choose(2^20, 20)` fourth-round bound. The focused module builds in 2.3
  seconds without enumerating the million-point domain.
- [x] (2026-07-30 03:18Z) Prove prefix-consistent logical XOF semantics, exact
  counter-mode/rejection-sampling refinement, and complete query accounting. The previous Lean
  oracle allowed unrelated outputs at different lengths; the completed model derives each bounded
  output from one shared counter stream and records every physical SHA-512 request.
- [x] (2026-07-29 13:18Z) Tested and rejected a complete-prefix challenge rewrite before changing
  production semantics. The PIOP message is reconstructed from high coefficients plus evaluations
  at the challenge points, so the verifier cannot absorb that full message before deriving those
  same points without circularity or transmitting the full polynomials. Restored the original Rust
  transcript unchanged and verified `cargo check -p transaction-circuit --lib`.
- [x] (2026-07-30 03:18Z) Prove exact chained-BCS database extraction for the existing compact transcript, treating
  each complete variable-output counter-mode XOF response as one logical verifier challenge and
  reducing its physical SHA-512 realization to an explicit hash-XOF assumption.
- [x] (2026-07-30 03:18Z) Complete the deterministic proof chain from canonical production bytes through parser,
  verifier checks, extracted witness, transaction relation, ordered block composition, and supply
  conservation.
- [x] (2026-07-30 03:18Z) Prove the SmallWood-specific interactive round-by-round extraction theorem, commitment
  multi-opening reduction, and concrete BCS/QROM loss in the finite model, or leave the release
  gate fail-closed if any of these remain an interface assumption.
- [ ] Run focused Lean builds, formal-core and formal-crypto gates, Rust tests, parser and transcript
  mutation campaigns, proving red-team tests, release tests, and a Codex Security diff review.
- [ ] Record exact measured artifacts and issue the final production or no-ship verdict without
  substituting an interface theorem, fixture, projection, or optimistic estimate for executed
  evidence.
- [x] (2026-07-30 03:18Z) Rebuilt `formal/lean` (199 jobs) and `formal/crypto` (2,531 jobs) on
  Lean 4.32.2, passed the 2,675-theorem axiom audit, and passed the final parser, native-path,
  PCS-forgery, compatibility, and CI-bounded adversarial gates.
- [x] (2026-07-30 03:18Z) Benchmarked the exact final frontier. The selected 64-lane candidate
  measured 184,875 wrapped bytes, 15.286 seconds proving, and 31.602 milliseconds verification;
  the rejected 128-lane candidate measured 234,026 bytes, 60.293 seconds, and 47.131 milliseconds.

## Surprises & Discoveries

- Observation: The active Rust policy and the top-level Lean no-counterfeit theorem describe
  different block objects.
  Evidence: `Hegemon.Consensus.ProofPolicy.inlineRequired` accepts independent transaction
  artifacts, while `AcceptedCanonicalBlock` still contains `provenBatch` and its top theorem
  requires equality with `expectedProvenBatchBinding`.

- Observation: The currently checked four-term `2^-128` SmallWood arithmetic is an interactive or
  classical-ROM error bound, not a 128-bit post-quantum attack-cost statement.
  Evidence: `HegemonCrypto.SmallWood.Qrom` proves the generic four-round transfer does not retain
  128 bits even at one oracle query, while `HegemonCrypto.SmallWood.BcsQrom` leaves the tighter
  round-by-round theorem and its constants as hypotheses.

- Observation: The active prover calls the BLAKE3 transcript backend and stores four 64-bit digest
  words.
  Evidence: `prove_candidate` selects `SmallwoodTranscriptBackend::Blake3`, and the proof engine's
  digest shape is 32 bytes. Generic quantum collision search on an ideal 256-bit digest is below the
  requested 128-bit work factor.

- Observation: The active proof's 104,527 bytes are fully accounted for; the largest components are
  36,901 bytes of opened witness scalars, 24,580 bytes of subset evaluations, 18,748 bytes of high
  coefficients, and 7,770 bytes of Merkle authentication paths. There is no large opaque wrapper
  that ordinary byte compression can remove.
  Evidence: The exact release proof-size report and corrected active-backend opening-surface report
  both decode and account for the production artifact.

- Observation: Packing the current committed relation at 64 field elements per row is the smallest
  tested geometry. Under the exact 256-bit interactive-error predicate, the smallest projected
  profile found is 163,700 bytes at a 1,048,576-point DECS domain with 25 queries.
  Evidence: `wide_margin_committed_relation_geometry_search` exhaustively tested packing factors
  16, 32, 64, and 128 and power-of-two domains from 32,768 through 1,048,576.

- Observation: Consecutive finite-difference domain extension, not transaction constraints or
  verification, dominates current proving. A checked radix-2 Goldilocks subgroup evaluator reduced
  production-shape domain evaluation from approximately 2.7 seconds at 32,768 points to 223.5
  milliseconds, and measured 453.9 milliseconds at 262,144 points.
  Evidence: Direct polynomial/NTT equivalence tests pass for power-of-two domains and the ignored
  production-shape benchmark completed with six Rayon workers.

- Observation: The existing checked compressed-relation design was the material byte reduction,
  not a wrapper change. It reduces the production relation from 1,531 rows and 1,722 nonlinear
  constraints to 699 rows and 890 constraints. The exact 64-byte-hash proof fell from 171,560 bytes
  to 117,806 wrapped bytes and proving fell from 3.561 seconds to 2.861 seconds.
  Evidence: `compressed_level5_relation_has_checked_699_by_890_geometry` passes its honest and
  mutation cases; `compressed_level5_radix2_roundtrip_benchmark` generated and verified the exact
  artifact.

- Observation: Expanding the DECS domain from 1,048,576 to 4,194,304 projects only a 4.7 KB
  reduction while multiplying the dominant evaluation-domain memory and work. The practical
  million-point profile is therefore preferable for production throughput.
  Evidence: The 699-row 64-byte-hash frontier projects 124,962 bytes at one million points and
  120,247 bytes at four million before canonical authentication-path deduplication.

- Observation: The active DECS challenge does not output 23 field words. Eight uniform Goldilocks
  words encode 23 indexes in base `2^20`, with a canonical first-valid nonce enforcing range and
  distinctness. The existing `[5, 36, 5, 8]` logical challenge-width vector is therefore correct.
  Evidence: `xof_decs_opening` computes `maxi = 3`, requests eight words, decomposes each into at
  most three indexes, sorts them, and accepts only a duplicate-free result.

- Observation: The current Lean variable-output oracle is under-specified. It may return unrelated
  outputs for the same preimage at different requested lengths, whereas the Rust SHA-512 XOF is a
  prefix of a counter-mode stream after Goldilocks rejection sampling. Four logical Fiat-Shamir
  stages also expand to multiple physical SHA-512 calls, notably five or more blocks for the
  36-word batching challenge.
  Evidence: `SmallWoodTranscript.hashWords` calls `oracle preimage outputWords` without a prefix
  law; `read_sha512_xof_words` increments a block counter until enough canonical field words have
  been accepted.

- Observation: The current SmallWood paper proves a classical-ROM straight-line extractor for the
  exact DECS/PACS/LVCS sequence. CMS supplies the quantum compressed-oracle/RBR route, including the
  concrete `6 t^2` database factor and `(2t+1)/2^lambda` instability term, but its theorem is stated
  for a specific chained BCS transcript. The active Hegemon domain-separated transcript requires
  an explicit compatibility proof or a versioned transcript change; domain separation by itself
  does not prove that compatibility.
  Evidence: SmallWood Theorem 9 and CMS Definitions 8.3-8.5, Lemmas 5.7 and 5.13, and Proposition
  8.14 in the current primary-source PDFs.

- Observation: Treating every physical SHA-512 counter block as an independent CMS verifier turn
  is invalid. The active DECS and PIOP coefficient challenges consume 690 and 91,710 accepted field
  words, respectively; after conditioning on all but one physical block, the last block need not
  satisfy the interactive round's average knowledge-error bound.
  Evidence: `HegemonCrypto.SmallWoodTranscript.activeDecsCoefficientWordCount` and
  `activePiopCoefficientWordCount` check to 690 and 91,710. The round-by-round theorem bounds one
  complete verifier message, not each block of its deterministic expansion.

- Observation: A full-prefix third challenge is incompatible with the current compact proof wire.
  The verifier reconstructs the full PIOP polynomials from transmitted high coefficients and their
  evaluations at the opening points, but those points are exactly the third challenge. Absorbing
  the reconstructed polynomial message before deriving the points is circular; transmitting the
  full message would materially enlarge every proof.
  Evidence: `piop_recompute_transcript` consumes `eval_points` to restore `ppol_highs` and
  `plin_highs`, while `canonical_piop_opening_points` derives those points from the transmitted
  `h_piop`.

- Observation: The earlier 117,806-byte Level-5 candidate does not satisfy the published DECS
  theorem. SmallWood Theorem 1 and the upstream reference implementation both use
  `binomial(N, d_decs + 2) * epsilon_D`; the branch used a much smaller factor with no located
  source. This invalidates the former 262-bit report without showing a concrete forgery.
  Evidence: SmallWood ePrint 2025/1085 Theorem 1, the DECS precursor ePrint 2023/1573 Theorem 1,
  and `smallwood/commit/decs/decs.py` all agree on the binomial factor.

- Observation: The former Lean oracle extractor interpreted the first 107 cells of an LVCS row as
  polynomial coefficients `20 .. 126`, but Rust and the upstream C construction interpolate a
  rotated value vector and therefore recover those cells by evaluating the polynomial at field
  points `20 .. 126`.
  Evidence: `lvcs_commit` appends 20 hiding values, rotates left by 107, and passes the rotated
  values to `decs_commit`; `stackedHeadCell` now evaluates `interpolatedCommittedRow` at
  `lvcsDataPoint`, and the complete dependent formal library rebuilds after the correction.

- Observation: Directly specializing a generic `Finset.univ` probability object to the
  1,048,576-position DECS domain caused Lean to materialize that domain during elaboration, using
  more than 8 GiB. The mathematically identical binomial-cardinality representation checks in
  seconds and does not enumerate the domain.
  Evidence: `SmallWoodLvcsOpening.discrepancyOpeningFailureProbability` is the exact
  `choose(root_count, 20) / choose(2^20, 20)` ratio, whose root-count bound is proved through the
  injective radix-2 evaluation map.

- Observation: Under the corrected theorem and the current 699-row Goldilocks relation, the
  byte-minimizing searched point is projected at 183,404 bytes using a four-million-point
  evaluation domain. The practical one-million-point point measures 184,747 bytes and spends
  approximately 8.3 of its 9.1 proving seconds on domain evaluation plus leaf hashing.
  Evidence: `compressed_level5_geometry_frontier_is_materially_smaller` and
  `compressed_level5_radix2_roundtrip_benchmark` pass with the corrected exact arithmetic.

- Observation: The first fixed-support Lean wrapper conflated the DECS evaluation-domain width
  with the committed-row residual width and assumed every 128-point support had a nonzero
  residual. The protocol guarantees only that at least one support is bad.
  Evidence: `SmallWoodDecsExtraction.exists_nonzero_lagrange_residual` constructs the witness;
  `NonzeroResidualSupport` now has separate support and residual dimensions; and
  `active_degree_enforcement_failure_probability_le` compiles against the exact active constants.

## Decision Log

- Decision: The active proof object is one canonical SmallWood proof per transaction. No recursive
  block proof, aggregation certificate, or proof-of-proof is part of this plan.
  Rationale: The user selected independent proofs after repeated aggregation artifacts increased
  on-chain bytes and proving latency. The active node already enforces that policy.
  Date/Author: 2026-07-28, Codex

- Decision: Privacy and Level-5-equivalent post-quantum soundness are hard constraints. Proof bytes
  are minimized subject to those constraints; no arbitrary proof-size threshold defines security.
  Rationale: Proof bytes directly consume block bandwidth, but reducing them by weakening security
  violates the product requirement.
  Date/Author: 2026-07-28, Codex

- Decision: “Formally verified up to hash assumptions” means that every deterministic and
  probabilistic link specific to Hegemon and SmallWood is proved, and the final theorem names only
  concrete properties of the deployed hash/XOF construction. A generic QROM theorem may be reused
  only if its exact statement is transcribed, pinned, applicable, and not represented as a local
  unproved field.
  Rationale: A structure whose fields are the desired security conclusions is an interface, not
  evidence.
  Date/Author: 2026-07-28, Codex

- Decision: Release authorization remains fail-closed until measurements and theorem closure both
  pass.
  Rationale: Green syntax, build, vector, or source-digest gates can still certify the wrong target
  or a conditional theorem.
  Date/Author: 2026-07-28, Codex

- Decision: Evaluate the wider-domain security profile on a radix-2 Goldilocks subgroup, but do not
  reinterpret historical proof bytes. The subgroup path must have its own version-bound production
  profile before activation.
  Rationale: The subgroup evaluator removes the measured proving bottleneck, while silently changing
  the evaluation points for existing proofs would break consensus compatibility.
  Date/Author: 2026-07-29, Codex

- Decision: Withdraw the earlier `beta = 2`, 23-query, `eta = 5` production target. Keep release
  authorization fail-closed until the corrected theorem-valid profile or a proved replacement
  degree test is selected.
  Rationale: The former profile was selected using an epsilon-one expression that conflicts with
  the published theorem and upstream implementation. Its size and speed remain measurements, but
  its claimed security does not.
  Date/Author: 2026-07-29, Codex

- Decision: Use a full uniform DECS batching matrix for the Level-5 format; retain scalar-power
  batching only in explicitly historical formats.
  Rationale: Uniform sampling gives the exact `epsilon_D = |F|^-eta` specialization stated by
  SmallWood Theorem 1 and removes the extra row-count factor from the production reduction.
  Date/Author: 2026-07-29, Codex

- Decision: Model the proof theorem over one prefix-consistent logical field-XOF and isolate the
  executable SHA-512 counter-mode/rejection-sampling implementation behind explicit collision,
  preimage, quantum-XOF, and domain-separation assumptions. Count all adversarial logical-oracle
  queries in the BCS theorem and all physical SHA-512 calls in the native refinement.
  Rationale: Treating one variable-output XOF request as one SHA-512 call is false, while expanding
  every accepted field word into the algebraic proof needlessly couples SmallWood to SHA-512
  internals. This split leaves only hash-construction security at the intended trust boundary.
  Date/Author: 2026-07-29, Codex

- Decision: Keep the active V4/Gamma compact chained transcript unchanged and formalize the
  original chained BCS extractor. Do not replace the third challenge with a complete-prefix query.
  Rationale: The complete PIOP message is unavailable until after its opening challenge. A direct
  full-prefix challenge would be circular or would require transmitting the full polynomials,
  violating the throughput constraint. CMS analyzes the chained BCS construction, so the correct
  closure is measured hash-chain extraction plus one logical hash-XOF assumption, not a larger
  proof.
  Date/Author: 2026-07-29, Codex

## Outcomes & Retrospective

The Hegemon-specific formal work is complete on this branch: canonical V4/Gamma bytes, exact
SHA-512 counter-mode expansion and rejection sampling, transcript reconstruction, physical query
accounting, compact-Merkle and round-by-round extraction, the finite CMS/QROM theorem, the exact
transaction relation, and ordered block supply composition all build from the top-level formal
library. Rust replays the canonical decoder and active verifier while constructing the corresponding
execution trace.

The result remains `candidate_under_review`, not production-authorized. The remaining boundary is
not an omitted SmallWood algebra theorem: it is the explicit assumption that domain-separated
SHA-512 realizes the modeled QRO and retains the stated collision/preimage properties, that
Poseidon2 retains its stated properties, and that arbitrary compiled Rust executions refine the
Lean evidence record. Passing vectors and trace replays test that last boundary but do not prove a
compiler, CPU, or operating-system semantics theorem. All 123 blueprint targets remain pending
independent review.

The final measured Pareto decision is to keep the 64-lane V4/Gamma candidate. The 128-lane
candidate adds 49,151 bytes and is 3.94 times slower to prove for only 3.205 additional bits in the
interactive arithmetic floor. Neither benchmark is itself a post-quantum security authorization;
the QROM theorem and explicit hash-instantiation assumptions are the relevant security statement.

## Context and Orientation

The repository root is `/Users/pldd/Projects/Reflexivity/Hegemon`. The working branch is
`codex/smallwood-pq128-experiment`. The tree is intentionally dirty with the current proof-system
work, so edits must preserve relevant changes and must not reset unrelated files.

The production prover and verifier live in `circuits/transaction/src/smallwood_engine.rs`,
`circuits/transaction/src/smallwood_frontend.rs`, and `circuits/transaction/src/proof.rs`. A
SmallWood proof commits to encoded witness rows, derives public challenges from a hash transcript,
and opens selected committed rows. “Interactive soundness error” is the chance that an invalid
oracle passes those random checks when challenges are honestly random. “BCS” is the transform that
replaces verifier interaction with hash-derived challenges and Merkle commitments. “QROM” is the
model in which a quantum attacker may query the idealized hash oracle in superposition.

The exact transaction relation and production-map refinement are modeled under
`formal/lean/Hegemon/Transaction` and `formal/crypto/HegemonCrypto`. The top block and monetary
composition theorem is
`formal/lean/Hegemon/Consensus/AcceptedSmallWoodBlockComposition.lean`. The active proof admission
policy is in `formal/lean/Hegemon/Consensus/ProofPolicy.lean` and the matching Rust native admission
path is under `node/src/native`.

`config/formal-security-claims.json`, `config/formal-security-blueprint.json`, and the formal-core
checker are release policy. They must distinguish a proved theorem from a hypothesis and must not
credit a retired batch object.

## Plan of Work

First, edit `AcceptedSmallWoodBlockComposition.lean` so `AcceptedCanonicalBlock` consists only of
the ordered independently verified transactions, canonical transaction claims, fees, data
availability fields, optional coinbase, block identity, and checked supply transition. Remove
`CanonicalProvenBatchBinding`, `expectedProvenBatchBinding`, and all active theorem premises that
bind a proven-batch artifact. Rename active “recursive” identity facts to independent transaction
identity facts. Update the generated positive and mutation vectors so a changed transaction proof
or claim fails direct composition without relying on a batch field.

Second, update the claim ledger, blueprint, README, DESIGN, and METHODS descriptions to match the
new theorem. Historical recursive decoding or replay may remain in explicitly compatibility-only
modules, but it must not be a dependency of active proof generation, mempool admission, block
construction, or the active no-counterfeit certificate.

Third, remove proof-of-proof and aggregation experiments from the dirty proof-engine changes while
retaining changes that directly improve independent proofs: canonical parsing, unbiased sampling,
first-valid nonce enforcement, exact integer soundness arithmetic, transcript tracing, parameter
search, and native refinement. Run the existing independent V3 roundtrip before changing security
parameters and capture exact bytes, stage timings, verification timings, and memory.

Fourth, define the final attack-cost predicate. The predicate must account for commitment collision
and preimage attacks, random-oracle output width, the round-by-round knowledge error, every quantum
oracle query in the BCS reduction, and concrete reduction constants. The accepted parameter set
must require at least `2^128` quantum work for the cheapest modeled forgery route. Increase digest
width and statistical margins only through a versioned proof format, then use an exhaustive integer
search to find nondominated parameter sets. Benchmark each nondominated candidate on the actual
transaction relation and keep the smallest candidate that satisfies the latency requirements.

Fifth, complete the Lean proof chain. Canonical proof bytes must decode to one profile and one
statement. Rust verifier acceptance must refine the Lean verifier. The Lean verifier plus the
SmallWood-specific extraction and binding theorems must produce the exact witness used by the
transaction relation. Ordered accepted transaction relations must imply the block supply theorem.
The final probabilistic statement must bound the probability of verifier acceptance without an
extractable valid Hegemon witness as an explicit function of adversary quantum-oracle queries and
hash assumptions.

Finally, execute all release and adversarial gates, review the diff for security regressions, and
record measurements. If any Hegemon-specific extraction, commitment, transcript, parser, or native
refinement theorem remains a hypothesis, set the production claim to no-ship and state the exact
remaining proposition. Do not promote an estimate or conditional theorem.

## Concrete Steps

All commands run from `/Users/pldd/Projects/Reflexivity/Hegemon`.

Inspect and build the corrected block theorem:

    lake env lean formal/lean/Hegemon/Consensus/AcceptedSmallWoodBlockComposition.lean

Run the exact active proof roundtrip with stage timing:

    HEGEMON_SMALLWOOD_TRACE=1 cargo test -p transaction-circuit \
      smallwood_candidate_roundtrip_verifies --release -- --ignored --nocapture

Run the warm verifier throughput benchmark:

    cargo test -p transaction-circuit \
      smallwood_candidate_warm_verifier_throughput --release -- --ignored --nocapture

Run the formal gates after each formal milestone:

    ./scripts/check_formal_core.sh
    ./scripts/check_formal_crypto.sh

Run focused active-policy and native-admission tests:

    cargo test -p consensus proof
    cargo test -p hegemon-node native

Run the proving red-team and complete release gates before any production verdict:

    ./scripts/run_proving_redteam.sh
    make check

The exact command names may be narrowed if the repository's test inventory provides a unique
fully-qualified target. Every executed command and outcome must be added to this document.

## Validation and Acceptance

Acceptance requires all of the following observable results.

The active Lean block theorem compiles and contains no proven-batch or recursive-proof premise. A
mutation of any ordered transaction proof, statement, fee, data-availability projection, coinbase,
or supply field causes its generated negative vector to reject.

The production node mines and imports blocks containing independent current-version SmallWood
transaction proofs, while new recursive candidate submission remains rejected. Historical replay
tests remain green without enabling historical formats for new production.

The exact release proof artifact reports its canonical byte count, proving time, peak resident
memory, verification time, and native admission time. The parameter report is generated from exact
integer formulas and lists all nondominated candidates considered.

The final Lean theorem has the form that verifier acceptance without extraction of a valid Hegemon
witness has probability at most an explicit `epsilon(q)`. The theorem's remaining premises are only
named collision, preimage, XOF pseudorandomness or ideal-oracle-instantiation properties of the
versioned production hash construction. It contains no premise equivalent to commitment binding,
AIR soundness, extraction soundness, parser correctness, verifier correctness, or the conclusion
itself.

All formal, Rust, mutation, adversarial, and release gates pass. A production-ready verdict is
permitted only if the measured cheapest quantum forgery route costs at least `2^128` operations and
the independent proof path meets the recorded operational latency envelope. Otherwise the outcome
is an explicit no-ship result with the failing inequality or theorem.

## Idempotence and Recovery

Source edits and test commands are repeatable. Do not delete user data, chain state, or historical
compatibility code. Generated proof fixtures must be written through existing generators and
checked for deterministic metadata before they are committed. If a cryptographic format changes,
retain old verification only in a version-scoped historical path and require an explicit activation
height before deployment. Never reset the dirty worktree; use file-scoped diffs and preserve
unrelated changes.

## Artifacts and Notes

At plan creation the active profile is circuit V3, crypto suite Beta, arithmetization tag 9, with
`rho = 3`, `nb_opened_evals = 3`, a DECS domain of 32768, 24 DECS openings, and a 32-byte digest.
The existing four exact error terms aggregate below `2^-128` only in the interactive/no-grinding
calculation. The formal QROM package explicitly does not promote that number to a production
post-quantum claim.

## Interfaces and Dependencies

No new recursive proof interface is permitted. The active Rust API remains a single transaction
proof produced and verified by the current SmallWood frontend.

The formal boundary must expose a concrete theorem, not a record populated by caller-supplied
security fields:

    Pr[production verifier accepts statement and proof
       and no witness satisfying the exact Hegemon relation is extracted]
      <= epsilon(quantum_oracle_queries)

`epsilon` must be an exact expression assembled from the proved round-by-round extraction and
Merkle multi-opening reductions plus explicitly named hash assumptions. The Rust parameter
attestation must derive from the same constants used by Lean.

Plan revision note (2026-07-28): Created after the active-path audit exposed a stale batch theorem,
an insufficient active digest width for the requested quantum collision work factor, and conditional
BCS/QROM and native-refinement boundaries.
