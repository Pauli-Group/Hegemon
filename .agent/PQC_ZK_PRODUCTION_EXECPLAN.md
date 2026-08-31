# Proposal-only PQC ZK transaction proof: mixed-field M4/BaseFold

> **Status: retained competitor, not selected production architecture.** The qualifying frontier
> is empty. The 488,460-byte number in this document is a static projection, not a compiled or
> measured strict proof: it does not price the unimplemented E384 coefficient-lane PCS, complete
> zero knowledge, or composed QROM losses, and its 83-permutation proof core externalizes hashes
> required by the current 79-invocation/124-permutation V6 relation contract. The active integration
> plan is `.agent/SMALLWOOD_SHAKE256_PRODUCTION_EXECPLAN.md`; this document remains useful only as
> a fail-closed competitor specification and can become a winner only after producing a smaller
> qualifying retained artifact under every common gate.

This ExecPlan is a living implementation document maintained according to
`.agent/PLANS.md`. `Progress`, `Surprises & Discoveries`, `Decision Log`, and
`Outcomes & Retrospective` must describe what is actually proved or measured.
A paper theorem, parameter screen, passing round trip, or small proof is not a
production security certificate.

## Purpose / Big Picture

Ship one wallet-created, self-contained proof for the exact maximum Hegemon
two-input/two-output and multimode transaction relation. The byte string
accepted by the wallet is the byte string relayed, mined, persisted, and
reverified by a fresh node during restart, sync, and reorganization. There is no
aggregate, receipt, sidecar, proof cache, or off-chain availability assumption.

The proposal-only competitor architecture is:

    exact HGF4ST02 action/statement adapter
      -> one-main native-word M4 SHAKE256-448 relation
      -> mixed-field Spartan/sumcheck over E384
      -> coefficient-lane BaseFold PCS committing compact B128 symbols
      -> SHAKE256-448 transcript and Merkle commitments
      -> exact 12-byte HGMP envelope

Here `B128` is the pinned GHASH field and `E384` is the genuine cubic extension
`B128[Y]/(Y^3 + Y + 1)`. B128 values remain the committed symbols. Algebraic
challenges, sumcheck claims, and folds live in E384. Three independent B128
challenges are a product ring with zero divisors and are forbidden.

The private proof core retains the measured 83 Keccak-f schedule. The current
maximum composed action path also performs 46 public Keccak-f permutations: 6
for `intent.1`, 1 for `bal.tag1`, 16 for each of two 2,147-byte `ct.hash1`
frames, and 7 for the 888-byte action-binding frame. The exact current
acceptance ledger is therefore 129 permutations, of which 83 are private-proof
work and 46 are deterministic public adapter work. This is permitted only after
a refinement theorem proves equivalence between composed acceptance and the
scalar relation. Raw M4 verification is never an exported authority API.

The engineering target is 491,520 bytes (480 KiB) and the immutable parser and
consensus cap is 524,288 bytes (512 KiB), including the 12-byte envelope. The
target is not a current measurement. The accepted production frontier remains
empty until the exact full relation, complete zero knowledge, composed
post-quantum/QROM security, parser/refinement, same-byte transport, and two
independent retained artifacts all pass.

## Progress

- [x] (2026-08-22) Read `AGENTS.md`, `DESIGN.md`, `METHODS.md`, the README
  whitepaper opening, and `.agent/PLANS.md`.
- [x] (2026-08-22) Audited the exact full SHAKE relation, action adapter,
  maximum M4 realization, retained strict-hash artifact, proof byte profile,
  frontier gate, and current disk gate.
- [x] (2026-08-22) Audited SmallWood's current implementation and the revised
  SmallWood paper, including its small-field construction, optimized proof-size
  equation, ROM extraction, and zero-knowledge theorem.
- [x] (2026-08-22) Rejected the earlier Goldilocks/shared-928 SmallWood
  projection: it treated characteristic-two XOR as Goldilocks-linear and its
  shared-row PCS was only a killed dimensional projection.
- [x] (2026-08-22) Compared Binius/BaseFold, SmallWood with SHAKE or BLAKE2b,
  FRI/WHIR/STIR, Ligero/Brakedown/Orion/Flock, VOLE/MPC-in-the-head, and
  lattice families against every hard gate.
- [x] (2026-08-22) Froze the mixed B128/E384 M4/BaseFold proposal and its
  projected byte-accounting/fail-closed gates for comparison. This is not a frontier selection.
- [x] (2026-08-22) Checked disk: 19,480,636 KiB was free, below the 28 GiB
  heavy-run admission floor and below the 20 GiB in-run reserve. No Cargo build
  or proof generation was started.
- [x] (2026-08-22) Implemented and direct-`rustc` validated the isolated
  B128/E384 scalar Reed--Solomon/BaseFold kernel: SHA-512 transcript and roots,
  B128 initial openings, three-lane E384 later openings, independent leaf
  tapes, distinct queries, canonical compact frontiers, exact parser/serializer,
  mutation rejection, and integrated fail-closed ZK rank audit. The last
  direct run passed 48 tests; the source now contains 51 after later ZK tests
  that were not rerun under the hard disk stop. This is not live M4 integration.
- [x] (2026-08-22) Corrected the retained M4 tree-depth screen. At inverse rate
  3, `q=319` is the conservative with-replacement 264-component count; exact
  without-replacement sampling needs q318, while freezing the incomplete
  ledger's other terms makes q310 its modeled composed->128 minimum. At q310,
  depths `13,18,20,11,16,12,9` project to 1,528,928 bytes before framing,
  masks, ZK repair, or production binding. This fixed-synthetic-transcript
  projection exceeds the retained 1,344,828-byte comparator, but is not a
  universal BaseFold lower bound or a production minimum. Common `2^20`
  padding at the older q319 screen is 4,145,888 bytes.
- [x] (2026-08-22) Bounded the E512 competitor on the identical schedule:
  mixed B128/E512 is 1,763,232 bytes and all-E512 is 1,883,136 bytes. E512
  either needs the same prover-channel split or widens the entire M4 scalar,
  so it cannot be the smallest repair on this schedule.
- [ ] Freeze and compile the exact maximum 83-permutation private M4 core and
  prove its composed equivalence to the current 129-permutation maximum
  acceptance path, including ciphertext canonicalization and action binding.
- [x] Stop the retained-tree E384 mixed channel before live productionization:
  its corrected q310 fixed-schedule projection is already 1,528,928 bytes,
  above the retained comparator before ZK/QROM repair.
- [ ] Screen the exact maximum relation under the one-level mixed-field
  Ligerito/TensorSwitch topology; compare full masks/tapes and complete-ZK
  bytes against every qualifying competitor without promoting the local
  524,288-byte parser screen to user or production authority.
- [ ] Implement and prove complete end-to-end zero knowledge for the exact
  joint transcript and accepted byte distribution.
- [ ] Close exact extraction, composed QROM security, hash instantiation,
  parser/refinement, and independent-review gates.
- [ ] Produce two independent maximum-shape proofs at or below 524,288 bytes,
  with at least one at or below the 491,520-byte engineering target.
- [ ] Carry one unchanged proof through wallet, relay, mined block, restart,
  fresh sync, and winning reorg, then activate only under a fresh rules hash.

## Surprises & Discoveries

- Observation: the exact maximum conventional-hash relation is already real,
  but its retained artifact is not a strict proof.
  Evidence: the source-bound artifact has an 853-byte statement, 83 private
  Keccak-f calls, 51,449 native-word AND constraints, 52,374 private words, and
  114 verifier-owned public words. Its three-copy SHAKE256-400 envelope is
  1,344,828 bytes, but complete ZK and a strict composed security claim are
  false.

- Observation: one current full-M4 BaseFold copy is close enough that a real
  strict single-proof design is worth building.
  Evidence: one retained SHAKE256-400 copy is exactly 448,224 bytes. Its byte
  profile contains 6,704 proof digests. Keeping the same topology and widening
  only those digests to 56 bytes gives the exact static SHAKE256-448 projection
  `448,224 + 6,704 * 6 = 488,448` bytes before the direct envelope. The same
  topology with 64-byte digests is 542,080 bytes. Neither projection prices the
  new E384 coefficient lanes or proves security.

- Observation: the compactness win requires a genuinely mixed interface, not
  a type alias.
  Evidence: a fold of B128 codeword values by an E384 scalar is E384-valued.
  Later rounds must either commit three B128 coefficient lanes or explicitly
  serialize 48-byte E384 values. Existing pinned Binius channels couple
  committed symbols, claims, and challenges to one `BinaryField` type and
  cannot express this.

- Observation: the isolated mixed-field seam is executable but is not the
  missing PCS.
  Evidence: `prototypes/standalone-shake256-binius/strict-mixed-field` pins the
  GHASH modulus, proves the cubic irreducible by Frobenius, implements E384
  multiplication/inversion/serialization, coefficient-lane folding, mixed
  transcript channels, parser counters, and product-ring negatives. Its toy
  proof transmits a full table and has no binding/hiding vector PCS.

- Observation: complete ZK cannot be obtained by appending random rows or
  masking only the trace commitment.
  Evidence: local negative controls expose annihilating verifier points,
  restricted-mask fibers, reused masks, and hidden-but-unbound terminal deltas.
  The accepted construction needs full-E384 masks for every visible linear and
  quadratic functional plus one joint simulator for trace, precommit,
  sumcheck, BaseFold, Merkle openings, terminal data, aborts, and selective
  failure.

- Observation: Boolean BLAKE2b is an architecture kill, not a compact
  alternative to SHAKE.
  Evidence: the exact 77-call framed relation expands to 164 RFC 7693
  compression blocks, 16,322,454 scalar witness values and constraints,
  255,100 packed-64 rows plus 462 output rows, before non-hash transaction
  logic. BLAKE2b-384 also has quantum collision exponent exactly 128 and no
  composition margin.

- Observation: the published SmallWood construction is not intrinsically tied
  to Poseidon, but a strict full-SHAKE port is not the small historical proof.
  Evidence: the paper's small-field proof alone contains the extension-field
  term `(dQ + n + ncols) * log2|K|`. Encoding the 51,449 word-AND relation as
  3,292,736 Boolean multiplications requires 6,585,472 operand cells. With
  E384, minimizing just `48 * (3s + 6,585,472/s)` already exceeds 426 KiB
  before DECS degree enforcement, openings, Merkle authentication, ZK, or an
  envelope. The old 87--118 KiB Poseidon-relation artifacts do not measure this
  relation.

- Observation: the local SmallWood strict screen uses a stronger DECS error
  than the revised paper proves.
  Evidence: SmallWood Theorem 1 and Equation (14) retain the factor
  `binom(N, ddecs + 2) / |F|^eta` for a uniform challenge matrix. The local
  engine and hardening profile use `1 / |F|^eta` and cite a one-affine-fiber
  argument. That improvement needs its own accepted extraction proof before
  the local `~2^-262.38` interactive and CMS figures can be strict evidence.

- Observation: the current host cannot safely run the maximum proof.
  Evidence: the last free-space check was below both the start and abort gates.
  Source, arithmetic, and lightweight direct tests are allowed; a heavy Cargo
  target or proof run is not.

- Observation: the old 488,448-byte projection omitted dominant strict terms
  and is not a production-size estimate.
  Evidence: at the conservative historical q319 screen, fixed synthetic roots
  need 11,912 opened E384 fold values, 11,400 SHA-512 frontier nodes, and 2,110
  independently taped opened leaves, projecting to 1,548,704 bytes. The
  incomplete-ledger q310 scaffold projects to 1,528,928 bytes. Neither is a
  transcript-independent lower bound or production parameter.

- Observation: live mixed-depth support exists only on the verifier side of
  the pinned channel split.
  Evidence: `FRIParams::optimal_for_batch` and
  `FRIQueryVerifier::new_batch` preserve the four input and three FRI depths,
  but prover `IPProverChannel<F>`, `FRIFoldProver`, and
  `MerkleIPProverChannel<F>` store/send/sample only `F`. The candidate now uses
  local path dependencies and a SHA-512 tree-digest checker, but the isolated
  PCS still does not implement the live M4 channel.

## Decision Log

- Decision: retain the exact native-word M4 plus genuine E384 mixed-field route as a bounded
  competitor proposal.
  Rationale: this is the only path with an executable exact maximum SHAKE
  relation, an exact sub-512-KiB single-copy topology anchor, and compact
  characteristic-two committed symbols. Every other candidate either expands
  the Boolean relation materially or lacks an exact full-relation artifact.
  Date/Author: 2026-08-22 / Codex.

- Decision: treat the current implementation as disqualified and withhold any architecture-winner
  label until it produces a qualifying artifact.
  Rationale: the current full artifact is sequentially repeated, not complete
  ZK, and not strict PQ128. Its sub-512-KiB result is only a projection that omits
  unimplemented mixed-field costs, so it cannot displace another route on projected bytes alone.
  Production authorization remains false until all gates pass.
  Date/Author: 2026-08-22 / Codex.

- Decision: provisionally use SHAKE256-448 for semantic digests and for proof commitment
  digests, with distinct registered domain strings, while sampling each E384
  challenge from exactly 48 fresh XOF bytes.
  Rationale: 384-bit proof digests have zero quantum-collision composition
  margin. A 448-bit digest has generic quantum collision work near `2^149.33`
  and saves eight bytes per proof digest versus 512-bit output. The global
  QROM accountant and standard-to-ideal gate must validate this choice. NIST
  caps SHAKE256 preimage strength at 256 classical bits regardless of longer
  output, so any unavoidable generic preimage term has only 128-bit quantum
  work before composition. If acceptance security cannot be reduced to the
  required collision/RO properties without that term, the affected semantic or
  proof role moves to a wider-capacity conventional construction such as
  SHA3-512 under a fresh profile. Merely widening SHAKE256 output to 512 bits is
  not a repair.
  Date/Author: 2026-08-22 / Codex.

- Decision: keep B128 commitments and materialize all later E384 values as
  exactly three authenticated B128 coefficient lanes.
  Rationale: this is a real field representation and gives an exact wire cost.
  Product-ring repetition, truncating a wide fold to one lane, or treating a
  transcript-derived challenge as making its wide responses free is rejected.
  Date/Author: 2026-08-22 / Codex.

- Decision: keep the 83-call private core and make public-only SHAKE
  recomputation part of the sealed composed verifier.
  Rationale: intent and balance hashes are deterministic functions of the
  canonical public action. Recomputing them before raw proof verification does
  not weaken witness soundness if exact parser/action/refinement equivalence is
  proved. A caller-supplied derived digest or exported raw verifier is forbidden.
  Date/Author: 2026-08-22 / Codex.

- Decision: preserve the known cumulative BaseFold wire optimizations only
  after byte-identical verifier reconstruction tests.
  Rationale: canonical compact Merkle frontiers, terminal-message commitment,
  verifier-known leaf reconstruction, public-message elision, and grouped
  co-commitment produced measured reductions on related M4 proofs. Each must be
  reimplemented against the mixed field and exact maximum relation; no ratio is
  assumed.
  Date/Author: 2026-08-22 / Codex.

- Decision (superseded): use 480 KiB / 512 KiB only as local engineering and
  parser screens, not as a user-selected proof objective or production cap.
  Rationale: the exact SHAKE448 one-copy topology anchor was 488,448 bytes
  before the direct envelope and mixed-field delta, but the user did not freeze
  512 KiB as the architecture-tournament boundary. Candidates must first be
  compared under the complete common security/relation gates.
  Date/Author: 2026-08-22 / Codex.

- Decision: assign a fresh statement/backend/profile/rules identity and fail
  closed throughout implementation.
  Rationale: no M4 weak-profile, three-copy screen, Poseidon SmallWood, BLAKE,
  Pay1x2, or prototype certificate applies to the new field, proof grammar, ZK
  compiler, or security theorem.
  Date/Author: 2026-08-22 / Codex.

- Decision: stop the retained 4+3-tree E384/E512 channel-port implementation
  at the isolated, fail-closed kernel unless its opening topology changes.
  Rationale: the corrected q310 E384 fixed-schedule projection is 1,528,928
  bytes, already above the retained 1,344,828-byte comparator before ZK/QROM
  repair. This is an implementation-route result, not a universal BaseFold
  lower bound or a 512-KiB production-cap decision.
  Date/Author: 2026-08-22 / Codex.

- Decision: make one exact maximum-relation, one-level mixed-field
  Ligerito/TensorSwitch screen the next bounded architecture test.
  Rationale: it is the narrowest route that removes the three wide FRI trees
  while reusing the M4 compiler and E384 arithmetic. Pay1x2/n14 figures are
  not accepted; the exact maximum relation, masks, tapes, parser, and complete
  ZK overhead must be priced before implementation continues.
  Date/Author: 2026-08-22 / Codex.

## Outcomes & Retrospective

This plan no longer retains the 4+3-tree E384 BaseFold wire as the smallest
implementation route. The executable scalar kernel is useful evidence, but
the corrected q310 fixed-synthetic-transcript projection for the retained
depths is 1,528,928 bytes before any ZK/security/production repair. The earlier
488,448-byte projection is superseded. E512 is larger on the same schedule.
SmallWood remains eliminated, and the one-level Ligerito/TensorSwitch successor
has not yet earned an exact maximum-relation result. None of these static
numbers is a production query count, cap, lower bound, or proof measurement.

Nothing is promoted. The retained maximum artifact is not complete ZK or
strict PQ128, the isolated mixed PCS is not the live M4 channel, and no
production proof exists. The production frontier remains empty. The next
bounded work is an exact one-level maximum-relation serializer screen; a live
backend port begins only if that screen has room for complete ZK and security
composition under the unchanged cap.

## Context and Orientation

The scalar source of truth is
`circuits/standalone-full-shake256-relation-prototype`. It owns the canonical
853-byte `HGF4ST02` statement, fixed two-input/two-output slots, four balance
slots, stablecoin rules, 9 accepted and 7 rejected activity masks, typed note
lineage, five private authorization modes, and SHAKE256-448 semantics.

`prototypes/standalone-shake256-binius/m4-full-production-prototype` is the
one-main native-word realization. The private circuit consumes 671 words and
the verifier owns 114 public words. Seven of those public words are the derived
intent digest computed by the composed adapter. The balance tag is likewise
recomputed from the action before proof verification. The source is research
only until the production modules and refinement certificates exist.

`prototypes/standalone-shake256-binius/m4-strict-full-shake400-v1` contains the
retained three-copy artifact and exact byte profile. It is geometry evidence,
not a security certificate. `prototypes/standalone-shake256-binius/strict-mixed-field`
contains the isolated E384 seam. `.agent/STRICT_MIXED_FIELD_BACKEND_EXECPLAN.md`
records the unresolved PCS, ZK, and QROM gates.

The production implementation should be additive under
`circuits/transaction/src/mixed_m4/` until activation. The intended modules are:

    relation.rs       exact private M4 relation and scalar differential adapter
    field.rs          pinned B128 and E384 arithmetic, basis, and serialization
    transcript.rs     domain-separated SHAKE256-448 mixed prover/verifier channel
    sumcheck.rs       E384 Spartan/sumcheck and degree ledger
    pcs.rs            B128 coefficient-lane vector commitment and openings
    basefold.rs       E384 folds over authenticated B128 coefficient lanes
    zk.rs             mask compiler, joint simulator, abort handling
    wire.rs           exact HGMP encoder/decoder and serializer counters
    profile.rs        immutable parameters, source fingerprints, security terms
    prover.rs         production prover and RNG distribution boundary
    verifier.rs       private raw verifier used only by the composed adapter

The public adapter belongs beside the transaction action/version parser, not in
the proof backend. It reconstructs the statement and derived public hashes,
then calls the private verifier. Wallet and node code call only that adapter.

## Architecture tournament

| Family | Best local evidence | Hard-gate verdict |
|---|---|---|
| Mixed M4 / BaseFold | Exact full relation; 448,224-byte SHAKE400 copy; executable E384 seam | Selected build path; current implementation disqualified until mixed PCS, complete ZK, QROM, and refinement close |
| SmallWood + SHAKE | Real hash-based PCS/PIOP and revised ROM ZK/extraction paper; local SHA-512 engine | Current candidates disqualified: compiled relations are Poseidon, the Goldilocks Boolean projection is invalid, and a strict full Boolean port has no artifact or QROM/refinement proof |
| SmallWood + BLAKE2b | Exact RFC 7693 trace | Disqualified: 16,322,454 scalar constraints before non-hash logic and no BLAKE2b-384 collision margin |
| Stock Binius / BaseFold | Exact maximum artifact | Disqualified: B128/96-bit algebra and incomplete joint ZK; three copies are 1,344,828 bytes |
| FRI / WHIR / STIR | STIR theorem-shaped screen is 403,392 bytes before production PIOP; local STIR swap gave only about 1.30x on the old AIR | Disqualified: no exact additive-characteristic-two mixed-field full-relation PCS, complete ZK, adaptive QROM proof, or retained production artifact |
| Ligero / Brakedown / Orion / Flock | Flock screen reaches about 142 KiB only for a reduced 70-Keccak, non-ZK, roughly 100-bit transcript | Disqualified: no same full relation, complete ZK, strict composed PQ128, parser/refinement, and same-byte artifact |
| VOLE / MPC-in-the-head | Executable screen: 6,374,400-byte generic Boolean term; best Keccak checkpoint forest 1,632,012 bytes | Disqualified on size and missing exact production gates |
| Lattice folding / lattice PCS | No local exact full-relation implementation or artifact | Disqualified: assumption and parameter choices alone do not satisfy relation, ZK, QROM, parser, or transport gates |

## Exact relation and binding contract

Define production acceptance as one composition, not two authorities:

    action = decode_exact(action_bytes)
    require canonicalize_each_active_ciphertext(action) == action.ciphertexts
    ciphertext_hashes = SHAKE448(each ct.hash1 frame)
    statement = reconstruct_HGF4ST02(action, network, rules)
    intent = SHAKE448(intent_frame(statement))
    balance = SHAKE448(balance_frame(statement))
    action_binding = SHAKE256_512(action_binding_frame(statement))
    public = statement || zero_pad_3 || intent
    require ciphertext_hashes == statement.ciphertext_hashes
    require balance == statement.balance_tag
    require action_binding == action.statement_binding
    require verify_HGMP_exact(public, proof_bytes)
    require transaction_action_matches_statement(action, statement)

Every length, endian conversion, mode tag, note kind, field order, inactive-slot
zero, ciphertext hash, anchor, nullifier, commitment, asset, fee, stable-policy
snapshot/CAS token, authorization state, network/rules identity, backend/profile
tag, and trailing byte is checked once under this composition. The proof
transcript observes the exact public transport and immutable relation-source
fingerprint before any prover message.

The formal target has separate completeness and extraction statements. In
particular, soundness must bind the extracted witness to this exact action; an
existential witness beside an already-accepted proof is circular:

    FullShakeRelation(action, witness)
      -> composed_verifier_accepts(action, Prove(action, witness; coins))

    composed_verifier_accepts(action, proof)
      -> canonical_action_and_ciphertexts(action)
         and FullShakeRelation(action, Extract(action, proof))

`Extract` is the knowledge extractor for the exact accepted mixed proof and
public adapter transcript. A theorem about an unbound M4 oracle, canonical
statement alone, a reduced action, or an unrelated existential witness is not
sufficient.

## Field and mixed-PCS contract

Pin exactly:

    B128 = GF(2)[X] / (X^128 + X^7 + X^2 + X + 1)
    E384 = B128[Y] / (Y^3 + Y + 1)

B128 serializes as one canonical 16-byte little-endian coefficient word. E384
serializes as three B128 coefficients `(a0,a1,a2)`, exactly 48 bytes. The
profile fingerprint covers both moduli, basis order, byte order, embedding,
challenge sampler, domain labels, and source revision.

The mixed channel has three distinct associated types:

    CommittedSymbol = B128
    Challenge       = E384
    Claim           = E384

The PCS commits an input B128 codeword directly. After an E384 fold, it commits
the three B128 coefficient codewords in one canonically ordered leaf. All three
lanes are authenticated; omitted coefficients are allowed only when the
verifier reconstructs them from prior authenticated values and a proved fold
identity before hashing the complete leaf. No projection from E384 back to
B128 is a binding operation.

The implementation must carry a machine-readable degree ledger from the M4
constraint reductions through sumcheck, ring switching, every fold, terminal
test, and batched opening. The ledger reports a maximum union degree `Dmax` and
the exact number of field-error targets. Production verification rejects if
the compiled geometry or degree ledger differs from the immutable profile.

## Complete zero knowledge

Zero knowledge means the entire accepted serialized view is simulatable for
every valid public statement, not that the witness oracle alone is masked.
The proof must include and bind fresh full-E384 randomness sufficient for:

1. every trace and precommit opening functional;
2. every linear and quadratic sumcheck round;
3. the grouped multiplication endpoint and terminal claim;
4. every coefficient-lane BaseFold and Merkle opening;
5. padding, inactive slots, and all five authorization modes; and
6. prover aborts, retries, malformed-proof paths, and selective failure.

The existing local kernel gives a useful exact rule: a linear E384 round costs
48 bytes of claim material and a quadratic round costs 96 bytes when those
claims are explicit; transcript-derived challenges cost zero bytes. Those
local affine-fiber results are necessary but not sufficient.

Required evidence is:

- an interactive joint simulator with exact or bounded statistical distance;
- a QROM Fiat-Shamir ZK lift covering programmed domains and aborts;
- a rank certificate for every witness-dependent verifier functional over the
  exact binary/B128/E384 bases;
- a compiled-prover distribution refinement theorem, including RNG/rejection
  sampling and memory initialization; and
- an independent review receipt bound to the exact source, profile, and two
  retained proofs.

Any simulator repair that adds wire bytes regenerates the profile identity,
byte report, artifacts, and security receipt. There is no `zk=true` flag based
only on tests.

## Composed post-quantum security

The interactive accountant includes at least:

    epsilon_field = sum_i degree_i / 2^384
    epsilon_fri   = exact BaseFold proximity/query bound
    epsilon_pcs   = exact coefficient-lane extraction/binding bound
    epsilon_int   = epsilon_field + epsilon_fri + epsilon_pcs + all unions

No `2^-96` upstream constant survives into the new profile. The checker derives
all query counts, rates, degrees, target multiplicities, and conditional
independence premises from the exact compiled profile. Shared Merkle roots or
query indices never multiply soundness by themselves.

The current ideal-QROM screen to be proved for this transcript shape is:

    Adv(t) <= 12*t^2*epsilon_int
              + 48*t^3/2^448
              + Merkle_QROM(t, targets, 448)
              + semantic_SHAKE_QROM(t, targets, 448)
              + ZK_distance
              + refinement_failure.

The constants and terms are obligations, not assumed truth. The final theorem
must cover the actual number and ordering of SHAKE domains, not independent
oracle names that the code does not instantiate. SHAKE256 standard-to-ideal
assumptions and all multi-target composition are explicit.

The security ledger classifies every hash use by the property actually needed:
collision resistance, target collision, preimage/one-wayness, hiding, PRF, or
programmable random oracle. It may not charge only the 448-bit output collision
term to a role that needs preimage resistance. NIST assigns SHAKE256 at most
256 classical preimage bits, so the conservative quantum term for one such role
already reaches the 128-bit work boundary before multi-target composition. A
strict receipt must therefore do one of two things: prove that no acceptance or
privacy break uses a generic SHAKE256 preimage event, or migrate each affected
role to a wider-capacity conventional primitive under a fresh relation/profile
and remeasure the circuit. Longer SHAKE256 output alone does not increase that
capacity-bound strength.

Two quantitative gates are mandatory under one declared global adversary and
system horizon:

    total_advantage(t = 2^64) <= 2^-128
    total_success(t = 2^128) < 1/2

The security ledger also charges generic quantum search against spend keys,
note randomness, rho, authorization secrets, every required semantic preimage,
and all system-level target counts. E384 and SHAKE448 are parameter capacity,
not a security claim. If any exact term fails, the profile stays inactive.

## Exact proof-byte equation and budget

The canonical writer returns counters from actual serialization. For one proof:

    proof_bytes = 12
                + fixed_bytes
                + 16 * explicit_b128_elements
                + 48 * explicit_e384_elements
                + 56 * (merkle_roots + merkle_auth_nodes)

`fixed_bytes` includes every collection length, round tag, salt/tape, nonce,
terminal header, and non-field scalar. An E384 value represented by three
coefficient lanes is counted once in `explicit_e384_elements`; it is not also
counted as three B128 elements. Transcript-derived challenges cost no wire
bytes, but their explicit responses and all committed coefficient lanes do.

The writer and exact decoder must agree on all five counters, and their
computed sum must equal the exact consumed file length. A static estimator is
never a frontier measurement.

The retained one-copy topology provides this nonqualifying anchor:

    SHAKE256-400 exact proof                    448,224 bytes
    proof digest count                           6,704
    static SHAKE256-448 topology projection     488,448 bytes
    direct HGMP envelope                             12 bytes
    static one-copy envelope                    488,460 bytes

The production budget is:

| Class | Engineering target | Hard maximum |
|---|---:|---:|
| Envelope, framing, fixed scalars | 4 KiB | 8 KiB |
| Roots, authentication, internal digests | 336 KiB | 352 KiB |
| B128/E384 algebraic and opened values | 120 KiB | 132 KiB |
| Terminal committed data | 12 KiB | 16 KiB |
| Reserve | 8 KiB | 4 KiB |
| **Total** | **480 KiB** | **512 KiB** |

The class limits are diagnostic; the serialized total and security gates are
authoritative. Known optimizations must reduce at least enough digest/opening
wire to pay for every new E384 lane and ZK message. The cap is not raised, a
digest is not truncated below 448 bits, and proof bytes are not moved outside
the transaction.

## Plan of Work

### Milestone 1: freeze the exact composed relation

Move the scalar relation, statement/action adapter, and one-main M4 source into
production-owned inactive modules. Compile the exact maximum circuit and emit a
source-bound geometry manifest. Differentially test every valid mode, all 16
activity masks, maximum values, empty/inactive slots, and every named semantic
mutation against the scalar oracle.

Prove that the sealed adapter's public intent and balance recomputations make
the 83-permutation private core, two ciphertext hashes, action binding, and all
other public predicates equivalent to the current 129-permutation maximum
scalar acceptance path. Delete or privatize every raw M4 verification entry
point. Stop if the compiled geometry exceeds the profiled n15 commitment tier
or differs from the source manifest; optimize semantics-preserving M4 wiring
before backend work.

### Milestone 2: productionize the mixed field and channel

Port the reviewed pieces of the isolated E384 prototype into `mixed_m4`, retain
the dependency-free KATs, and add independent Sage/Lean or equivalent field
checks. Split prover/verifier channels into committed, challenge, and claim
types. Observe the exact relation fingerprint and public transport before any
message, sample exactly 48 XOF bytes per E384 challenge, and reject every old
B128-only profile at parse time.

At the end, randomized field/fold differential tests, canonical serialization,
wrong-basis, wrong-domain, truncation, product-ring, and transcript-order
negatives pass. This milestone still has no compact PCS or security claim.

### Milestone 3: implement coefficient-lane BaseFold

Implement one immutable B128 input commitment, three-lane E384 later-round
commitments, canonical compact multiproofs, terminal-message commitment,
verifier-known leaf reconstruction, and grouped co-commitment. The prover and
verifier share one exact fold specification and degree ledger. Build small
domains first and compare a simple full-table reference with the compact PCS
for every challenge and opening.

At the end, the maximum relation proves and verifies in the new profile,
mutation and exact-consumption tests pass, and the serializer emits a complete
byte breakdown. The proof remains non-authorized until ZK and security close.

### Milestone 4: close complete ZK

Implement the full-E384 mask compiler and bind every mask source before its
challenge. Write the joint simulator, abort-conditioned proof, rank ledger,
compiled-prover distribution refinement, and RNG refinement. Test all modes,
padding shapes, repeated statements, adversarial challenges, mask reuse, zero
rank, hidden-delta, and selective-abort negatives.

If any view is not simulatable, change the protocol and return to Milestone 3.
No proof artifact or byte target outranks complete ZK.

### Milestone 5: close extraction and QROM security

Prove round-by-round knowledge extraction into the exact scalar witness,
coefficient-lane PCS binding, BaseFold proximity soundness, all field degree
terms, and the actual SHAKE256-448 Fiat-Shamir/Merkle composition in the QROM.
Prove accepted-Rust parser/verifier refinement and the composed public-hash
equivalence. Have an independent reviewer pin the receipts under a separate
trust root.

The exact calculator must pass both quantitative gates and print every term.
If a SHAKE256 preimage/capacity term or any other SHAKE448 term lacks margin
under the final system horizon, create a wider-capacity conventional-hash
relation/profile and rerun geometry and byte gates. Do not silently widen XOF
output under the same proof identity and call the capacity problem fixed.

### Milestone 6: optimize and retain two qualifying proofs

Run the byte optimizer only across theorem-preserving choices: leaf packing,
canonical multiproof frontier, fold arity/rate/query schedule, terminal size,
public reconstruction, and redundant authenticated values. Every candidate is
generated by the same exact relation and is rejected unless the security
calculator and complete-ZK receipts apply to its exact profile.

Retain two independently randomized maximum-shape proofs, their canonical
actions/witness commitments, source manifests, profiler reports, RSS/timing,
serializer counters, and hashes. Both must be at most 512 KiB; at least one must
be at most 480 KiB. A smaller byte count with any false capability is not a
frontier point.

### Milestone 7: same-byte integration and fail-closed activation

Wire wallet proving and self-check, RPC/mempool admission, relay, miner block
encoding, persisted storage, restart replay, fresh sync, and reorg replay to the
same composed adapter and exact decoder. Record the proof digest at each handoff
and assert byte equality. A fresh node starts with no cache and rechecks the
embedded proof.

Activate only under a fresh rules hash after the independently pinned relation,
ZK, PQ128, parser/refinement, two-artifact, and same-byte receipts all pass.
Missing, stale, malformed, self-issued, or mismatched receipts make build or
activation fail. There is no runtime fallback to Poseidon or a weak backend.

## Concrete Steps

All commands run from `/Users/pldd/Projects/Reflexivity/Hegemon`. Before any
heavy build or proof:

    git status --short
    df -Pk .

Do not start a heavy run with less than 28 GiB free. The supervisor aborts if
free space falls below 20 GiB, process-group RSS exceeds 8 GiB, its owned Cargo
target exceeds 4 GiB, or its owned run root exceeds 5 GiB.

Run the lightweight scalar, field, and formal checks first:

    cargo test --offline --locked \
      --manifest-path circuits/standalone-full-shake256-relation-prototype/Cargo.toml
    cargo test --offline --locked \
      --manifest-path prototypes/standalone-shake256-binius/strict-mixed-field/Cargo.toml
    bash scripts/check_lean_formal.sh
    git diff --check

Expected current result: scalar and isolated field tests pass, while the new
production authorization checker remains fail-closed because its receipts do
not exist.

After Milestones 1--3 add these focused commands:

    cargo test --offline --locked -p transaction-circuit mixed_m4_relation
    cargo test --offline --locked -p transaction-circuit mixed_m4_field
    cargo test --offline --locked -p transaction-circuit mixed_m4_basefold
    cargo test --offline --locked -p transaction-circuit mixed_m4_wire
    cargo clippy --offline --locked -p transaction-circuit \
      --all-targets -- -D warnings

The exact profile calculator is invoked as:

    cargo run --offline --locked -p transaction-circuit \
      --bin hegemon-mixed-m4-profile -- \
      --profile hegemon.m4.e384.basefold.zk.shake448.v1 \
      --max-proof-bytes 524288 \
      --target-proof-bytes 491520 \
      --json /private/tmp/hegemon-mixed-m4-profile.json

It must print compiled relation/source fingerprints, the current maximum ledger
of 83 private plus 46 public Keccak-f permutations, exact
field/query/rate/degree parameters, every serializer counter, both QROM gates,
and capability flags. Until receipts close, it exits nonzero under
`--require-release`.

The supervised maximum proof run is:

    python3 scripts/run_mixed_m4_proof.py doctor
    python3 scripts/run_mixed_m4_proof.py prove-and-verify \
      --profile hegemon.m4.e384.basefold.zk.shake448.v1 \
      --max-proof-bytes 524288 \
      --target-proof-bytes 491520 \
      --min-free-gib 28 \
      --abort-free-gib 20 \
      --max-rss-gib 8 \
      --max-target-gib 4 \
      --max-run-root-gib 5 \
      --reproductions 2

The command must print two different artifact hashes, exact byte counts and
counter sums, fresh-process verification, all mutation rejections, and the
independently read capability receipts. A proof generated while any capability
is false is retained only as a non-frontier diagnostic.

After formal/security integration:

    bash scripts/check_formal_crypto.sh full
    python3 scripts/check_mixed_m4_production_authorization.py \
      --profile config/mixed-m4-e384-shake448-v1.json \
      --claims config/formal-security-claims.json \
      --require-release
    cargo test --offline --locked -p wallet mixed_m4_same_bytes
    cargo test --offline --locked -p hegemon-node mixed_m4_restart_reverify
    cargo test --offline --locked -p hegemon-node mixed_m4_fresh_sync
    cargo test --offline --locked -p hegemon-node mixed_m4_reorg_replay

Final fresh-clone/node validation follows the repository runbook:

    make setup
    make node
    HEGEMON_MINE=1 \
    HEGEMON_SEEDS="hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333" \
      ./target/release/hegemon-node --dev --tmp

All miners on a shared network use the same approved `HEGEMON_SEEDS` list to
avoid partitions and forks. Every host enables NTP or chrony because
future-skewed PoW timestamps are rejected.

## Validation and Acceptance

The relation gate requires scalar/M4 differential agreement on every mode,
all 16 activity masks, random valid witnesses, maximum values, inactive slots,
and every named mutation. The composed verifier must recompute the two public
hashes, consume the exact 853-byte statement and 912-byte public transport, and
have no callable raw-authority path.

The parser gate requires exact consumption and rejection of wrong
magic/version/backend/profile/source fingerprint, noncanonical B128/E384
encoding, overflow, truncation, trailing bytes, wrong dimensions, duplicate or
unsorted multiproof nodes, wrong action/network/rules source, and every fresh
proof over a forged statement.

The ZK gate requires the joint interactive and QROM simulators, rank ledger,
abort/selective-failure proof, compiled-prover and RNG refinement, and
independent receipt for the exact profile. It applies to the full witness and
all modes with no excluded transcript message.

The security gate requires exact extraction into the full scalar witness,
mixed-PCS and proximity theorems, exact degree and query accounting, SHAKE448
standard-to-ideal/multi-target terms, system-level secret search terms, and
both quantitative QROM inequalities. Labels such as E384, PQ128, or ZK do not
substitute for these receipts.

The size gate requires two retained exact-parsed maximum proofs no larger than
524,288 bytes, with one no larger than 491,520 bytes. The writer's equation
must equal each file length. No aggregation, sidecar, cache result, omitted
coefficient lane, reduced relation, truncated digest, or unpriced ZK material
is allowed.

The same-byte gate requires one proof digest and byte string to remain identical
at wallet self-check, mempool, relay, mined block, storage, restart, fresh sync,
and winning reorg. Verification must succeed from a fresh database without an
external artifact.

The production gate requires all receipts under the separate trust root and a
fresh activation identity. Until then proving and verification return an
explicit unsupported-profile error before expensive work.

## Idempotence and Recovery

All production work is additive until activation. Parameter, field, hash,
relation, parser, or wire changes require a fresh profile identity and fresh
artifacts; historical receipts are never edited into acceptance.

Heavy runs use UUID-named owned directories with an ownership marker. On
failure, terminate only that owned process group, preserve the small manifest
and logs, and remove or trash only the exact owned target/run root after
checking the marker. Never run broad `cargo clean`, delete shared caches, or
remove repository/user data to create space.

If compiled geometry leaves n15, the proof exceeds 512 KiB, a ZK view lacks
rank, the security calculator fails, public-hash equivalence is unproved, or
any retained artifact disagrees with the exact parser, production remains
disabled. Optimize theorem-preserving layout or select a fresh profile; do not
weaken the relation, security target, hash width, same-byte invariant, or
fail-closed policy.

## Artifacts and Interfaces

Durable evidence created by this plan will include:

- an immutable profile JSON with field/hash/source fingerprints and parameters;
- a compiled maximum-relation geometry and degree-ledger manifest;
- exact serializer-counter reports and two retained proof files;
- scalar/M4 differential and parser mutation reports;
- complete-ZK simulator, rank, abort, RNG, and prover-refinement receipts;
- extraction, mixed-PCS, QROM, SHAKE, Rust/Lean refinement, and independent
  review receipts; and
- wallet/relay/block/restart/sync/reorg same-byte reports.

The profile checker reads these artifacts; it never trusts a boolean written by
the prover. Each receipt names the exact source digest, profile digest, public
statement digest, proof artifact digest where applicable, theorem/checker
version, and independent signer/trust-root entry.

The primary protocol references are the pinned Binius64 source revision used by
the local artifacts, the SmallWood revised paper
([ePrint 2025/1085](https://eprint.iacr.org/2025/1085)), and the QROM compiler
premises tracked by the existing formal hardening work
([ePrint 2019/834](https://eprint.iacr.org/2019/834)). FIPS 202's SHAKE256
security-strength ceiling is part of the role-by-role hash gate
([NIST FIPS 202](https://csrc.nist.gov/pubs/fips/202/final)). These references
guide the proof obligations; only the exact implemented-byte refinements
authorize Hegemon.

Revision note (2026-08-23): the mixed-field route remains a proposal after red-team review. Its
exact current artifact is nonqualifying and its 480/512-KiB figures are engineering projection
gates, not proof measurements. No production capability, architecture win, or frontier point is
claimed.
