# Ship the smallest conventional-hash self-contained transaction proof

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`,
`Decision Log`, and `Outcomes & Retrospective` must be kept current while work proceeds.
Maintain this document in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

Hegemon must admit one canonical, self-contained zero-knowledge proof for every shielded
transaction. The wallet must create that proof once, and the identical bytes must remain the
consensus authority through RPC submission, peer relay, the durable mempool, mining, block
storage, synchronization, reorganization replay, and validation by a fresh node. The proof must
cover the complete fixed two-input/two-output Hegemon transaction relation, use conventional
hashes rather than Poseidon as a security authority, provide complete zero knowledge, and retain
at least 128 bits of composed post-quantum security in the QROM after every proof-system,
Fiat--Shamir, hash-instantiation, grinding, and union term is charged.

The architecture tournament has disqualified the current SmallWood occurrence-row Boolean adapter
on exact serialized geometry: its hash-only row lower bound is more than 1.25 million rows, its
SMZ2 wire cannot encode the resulting columns, and its static proof lower bound is about 75.6 MB
before non-hash logic. That result does not disqualify the reusable SmallWood LPPC/DECS engine.
A fresh direct radix-4 word/bit arithmetization has re-entered the tournament provisionally. Its
frozen fail-closed checker now accounts for the two dependent feedforward stages, mode-selected
RFC counter/final initialization words, and a conservative mode-gated state2/state3 authorization
digest link: at K=1024 it conditionally projects 11,054 hash-core rows plus 48 source and 107
message rows, 11,209 base rows total, and 1,373,074 static inner-wire bytes. K=1024 and K=1029 are
byte co-minima; K=1024 is retained only as the deterministic
whole-word/fewer-cell tie-break. The dense topological indexer that must align every operand/result
tuple is not implemented, and mode-gated state2/state3 digest selection plus the non-hash relation
are not included, so this is neither an exact executable trace nor a proof measurement. More
fundamentally, red-team execution has disqualified the inherited transaction grammar: it admits
an output-only permissionless stablecoin mint, treats `max_mint_per_epoch` as a reusable per-
transaction magnitude limit, never consumes `min_collateral_ratio_ppm`, and leaves an output-only
anchor unconstrained inside the relation. The fresh packing factor, wire, complete-ZK
construction, repaired exact full relation, and security composition are not implemented. The
tournament winner therefore remains null; the retained Binius/M4 artifact is a size comparator,
not a qualifying baseline. The uniform SHAKE256-448 relation is retained only as executable rejected
candidate: secret-derived note/nullifier/spend/policy/authorization roles require preimage,
PRF/KDF, or hiding security, and SHAKE256's 512-bit capacity gives exactly 128 bits under Grover
before composition. The next successor must use a standardized wide-capacity conventional
primitive for those roles and may retain SHAKE256-448 only where a reviewed reduction needs
collision binding. The inherited RFC
7693 BLAKE2b gadget is retained as exact implementation evidence,
but the Boolean BLAKE2b-384 profile is disqualified: 384-bit output has no composition margin, and its
already-incomplete 77-call/164-compression schedule costs exactly 16,322,454 scalar constraints /
255,100 per-call packed-64 core rows, plus 1,906 input-binding and 462 output-binding rows, before
transaction logic. Adding the two omitted full ciphertext
hashes can only make that losing geometry larger. This selection is not an
authorization. It loses immediately if another implemented architecture produces a smaller
retained proof while satisfying every gate below.
No result from a 96-bit, SHA-256, GF(2^128), incomplete-ZK, sidecar, aggregate, receipt, cache, or
partial-relation profile is comparable to the qualifying frontier.

The inherited `q48/s6/eta5` SmallWood profile is now separately disqualified by the published
SmallWood soundness theorem. Theorem 1 / Equation (14) charges
`binom(N, d_DECS + 2) / |F|^eta` even for a uniform coefficient matrix; the live engine's
`|F|^-eta` branch relies on an unretained custom extractor strengthening. At the frozen transcript
fixture (`N=2^20`, `L=5970`, `d_DECS=L+48-1=6017`, Goldilocks), the published epsilon-one bound
already exceeds one at `eta=5`. Exact integer screening of that one term after the `12*Q^2`,
`Q=2^64`, CMS loss first clears the strict `2^-128` target at `eta=840`; serializing the additional
DECS high coefficients and 48 opened masking values adds `40,200,240` bytes relative to `eta=5`,
before every other term and wrapper. This is a fixture sensitivity, not the final adapter geometry,
but it already exceeds the dormant transport's 4 MiB implementation ceiling. SmallWood remains in
the tournament only if a retained, independently refined theorem removes that support union or a
different paper-valid parameterization is proved smaller. No bare-`|F|^-eta` projection may be
used as security or proof-size authority.

## Progress

- [x] (2026-08-22 19:49Z) Created the persistent goal with the exact requested objective.
- [x] (2026-08-22 19:55Z) Read `AGENTS.md`, `.agent/PLANS.md`, and the canonical `README.md`;
  dispatched complete read-only reviews of `DESIGN.md` and `METHODS.md` and inspected their
  transaction-proof sections before any edit.
- [x] (2026-08-22 20:02Z) Confirmed the disk gate is closed: the data volume had about 19 GiB free,
  below the 28 GiB heavy-run admission threshold and inside the 20 GiB hard-stop margin.
- [x] (2026-08-23 01:45Z) Rechecked after inherited focused Cargo work: only about 18 GiB remains.
  No further Cargo, Lake, proof, or other heavy build may start until the explicitly approved disk
  gate is restored to at least 28 GiB.
- [x] (2026-08-22) Reasserted the hard abort after later offline checks grew the repository target;
  the most recent readback is 16,841,448 KiB (about 16.06 GiB) free. All workers acknowledged the
  stop. The exact first-pass rebuildable cleanup proposal is repository `target/`
  (7,153,278,976 bytes), `/private/tmp/hegemon-shake400-target` (3,083,841,536 bytes), and the
  Homebrew download cache (8,426,319,872 bytes), 18,663,440,384 bytes total and about 33.56 GiB
  projected free. Repo/temp cleanup alone would remain below the 28-GiB gate. Reserved optional
  cache targets are `formal/crypto/.lake`, `hegemon-app/dist`, `hegemon-app/.electron-vite`, and
  `hegemon-app/node_modules/.vite`; none of these paths may be removed without the user's explicit
  approval.
- [x] (2026-08-22 15:37Z) Rechecked the disk gate after external space changed: the data volume now
  reports 31,889,396 KiB (about 30.4 GiB) free, so the 28-GiB admission threshold is open but the
  20-GiB hard abort remains controlling. Replayed the new fail-closed V5 transport crate tests
  independently (6/6 pass). A transaction-crate replay was stopped after the shared, concurrently
  edited `smallwood_blake2b384_semantics.rs` failed type-check with eleven unresolved/moved-value
  errors; no envelope or transaction proof test is credited from that command, and no further
  heavy build will start until the owned lowering source reaches a stable handoff.
- [x] (2026-08-22) Rechecked the shared volume during the HX512 freeze: it first reported
  29,364,432 KiB and then 29,333,404 KiB (about 27.97 GiB) free. The build-admission gate is now
  closed. No Cargo, proof generation, or other build was started; only already-built isolated
  binaries and source-only checks are admissible until materially more space exists. The 20-GiB
  hard abort remains binding.
- [x] (2026-08-23 02:17Z) Reconciled the architecture tournament against live source and retained
  measurements. SmallWood/SHAKE was the provisional leader at this checkpoint; the later exact
  Boolean-row gate supersedes that decision. The 1,344,828-byte Binius/M4 artifact,
  the incomplete Boolean-BLAKE2b schedule, and every host-externalized 83/90-permutation SHAKE
  projection are nonqualifying. This decision is provisional until a qualifying retained proof
  exists; the production frontier remains empty.
- [x] (2026-08-22 21:12Z) Retained the exact RFC 7693 Boolean gadget as negative tournament
  evidence. Its isolated 10-test/KAT suite and Clippy passed; its measured static geometry rules it
  out of the smallest-proof lane and it remains disconnected from production.
- [x] (2026-08-23 02:42Z) Disqualified the uniform SHAKE256-448 semantic profile on the exact
  security-role gate. `note.cm3`, `nullif.2`, `sp.keys2`, `policy.1`, and both authorization
  pipelines have unavoidable preimage/PRF/KDF/hiding terms capped at exactly 128 PQ bits before
  composition. A typed mixed-role registry and standardized wide-capacity Boolean seam are now
  required under a fresh successor profile; no current 79/124 identity may become production
  authority.
- [x] (2026-08-23) Froze the fresh mixed successor's descriptor identity without authorizing it:
  `HGF6ST02`/`HEG-F6V2`, profile 3/domain set 2, `HGF6HR02`, `HGR6RM02`, SWV6 envelope version 2,
  `HGV6PB02`, and `SMZ2`. The typed 214-byte role registry derives 79 calls/145 permutations;
  the exact 546-byte descriptor manifest binds to
  `7bc4270f9dc4b8c8e23a8c04abfa193dc820d4c90a49abf7370b8c862052e146d673e4b943bb251d6fc3167db96892c3c9c2598c6df88b7855541984251a5fc5`.
  PB02 is 1,114 payload bytes, 1,128 aligned bytes, 141 little-endian words, and zero alignment
  bytes. An isolated statement/manifest harness passes 11/11; old profile-2/domain-1 identities
  reject. This manifest still binds descriptors, not a frozen executable relation.
- [x] (2026-08-23) Disqualified that profile-3/HGF6HR02 descriptor before backend promotion.
  FIPS 202 and RustCrypto define SHAKE128 and SHAKE256 only; the registry's rate-72,
  capacity-1024, suffix-0x1f `SHAKE512` is a novel Keccak XOF rather than a conventional named
  primitive. HGF6ST02/HGR6RM02/HGV6PB02/SMZ2 remain rejected evidence and must never be
  reinterpreted. A fresh identity is required after choosing a standard wide-capacity primitive.
- [x] (2026-08-23) Disqualified the landed SmallWood Boolean adapter as the smallest architecture.
  For packing 64, rho/opened/eta 5, beta 2, q 23, degree 5, and full 64-byte commitments, the exact
  strict inner-wire formula is
  `60,114 + 2,920*D + 40*R + 40*ceil((R + 5*D + 10)/2)` bytes. At `D=5` it exceeds the retained
  1,344,828-byte M4 artifact at row 21,157. Source-linked hash-only inventory already gives
  17,968,396 wires, 280,757 canonical rows, 977,812 occurrence rows, and `R >= 1,258,569`, for a
  static lower bound of 75,589,554 bytes before public/source equalities or non-hash constraints.
  The SMZ2 `u16` matrix-column grammar also hard-fails at that shape. A radically different
  Boolean arithmetization/PCS is required; an adapter tweak cannot rescue SmallWood.
- [x] (2026-08-22) Superseded the blanket SmallWood-engine disqualification after screening a
  fundamentally different direct radix-4 arithmetization. The corrected provisional K=1024 layout
  initially conditionally packed the 90-call/213-compression HX512 core into 11,051 rows, added 48
  source and 107 message rows, and projected a 1,372,874-byte static strict payload with 460
  authentication nodes and no wrapper. That screen omitted 639 initialization/control XOR words,
  at least twenty K=1024 rows before exact source/broadcast bindings. K=1029 tied only in the stale
  formula; the optimizer must rerun after the control topology is complete.
  It avoids the occurrence-row explosion by using exact radix-4 range/XOR identities, linear carry
  recurrences, fused ternary additions, and dense same-role packing. The result is source-static:
  A secret-independent dense topology indexer, full non-hash rows, a Rust K=1024 wire/parser,
  complete-ZK proof, composed security, and measured proof bytes are absent. SmallWood re-enters
  provisionally; no winner or authority is assigned.
- [x] (2026-08-22) Corrected the radix-4 screen through the conservative mode-gated auth-digest
  link. The arithmetic projection is K=1024, 11,054 core + 48 source + 107 message rows, degree 6,
  1,373,074 static inner bytes, with K=1029 tied on bytes. The worker's checker and 9 tests,
  including 31 fail-closed mutations, passed at its checkpoint. Independent replay then correctly
  failed closed because the separately owned diagnostic compiler test changed its pinned hash
  during finalization. No stale artifact or hash is accepted; the screen must be regenerated and
  independently replayed only after that disqualified compiler is frozen. The public indexer,
  non-hash rows, complete ZK, joint security profile, executable proof, and production identity
  remain null.
- [x] (2026-08-22) Disqualified the inherited stablecoin/full-relation language after executable
  red-team counterexamples. An enabled SingleKey mask `0100` transaction can mint a non-native
  output without any input or issuer secret; two transactions can each consume the entire nominal
  per-epoch cap because there is no authenticated `minted_before -> minted_after` transition; and
  an output-only transaction leaves the proof's anchor unconstrained. Source inspection confirms
  that `min_collateral_ratio_ppm` is hashed but never evaluated and oracle/attestation commitments
  have no opened source or authorization semantics. Production remains fail-closed pending a fresh
  consensus-owned policy/issuer/oracle/attestation/cumulative-state grammar and compiler.
- [x] (2026-08-22) Stopped the superseded parent task and all eight overlapping shared-checkout
  workers after repeated concurrent edits and recursive formatting changed relation sources.
  Verified that no cargo/rustc/rustfmt process remained, `git diff --check` passed, and froze exact
  hashes for sixteen critical files in
  `.agent/hardening/smallwood-source-checkpoint-20260822T154918Z.json`. Only one scoped Rust writer
  may proceed from that checkpoint at a time.
- [x] (2026-08-22) Harden the reusable engine's generic CSR boundary before any new compiler may
  rely on it. The scoped source repair now validates checked `row_count * packing_factor`, the
  complete `u32` witness-plus-auxiliary variable space, canonical auxiliary words and padding,
  `L+1` strictly increasing nonempty offsets, exact term/target lengths, a final offset equal to
  the term count, nonzero canonical coefficients, canonical targets, unique in-row indices, and
  every index below the checked variable count. It also removes the former silent out-of-range
  term/auxiliary skips and validates configuration before proof decoding in both verifier paths.
  After the prospective stablecoin writer froze its file, the root independently replayed all six
  `generic_csr` tests, the malformed-linear-metadata identity regression, and
  `cargo check -p transaction-circuit --lib --locked`; all pass. The frozen engine SHA-256 is
  `03161861d0afbcfad27456d6a59ce70093531271d2761fa740425eb0045a3446` and
  `.agent/hardening/smallwood-generic-csr-repair-20260822.json` records the repair boundary.
- [x] (2026-08-22) Land and independently replay an executable, canonical, but inactive
  stablecoin V3 transition after disqualifying the inherited permissionless mint. The fixed wire
  is 175 bytes per state row, 435 bytes per membership proof, 315 public bytes, and 684 witness
  bytes. Mint authenticates the issuer, cumulative epoch mint and debt successor, lifecycle,
  oracle, attestation, and collateral ratio; burn deliberately bypasses stale/disputed/retired/
  undercollateralized risk gates so debt reduction cannot be frozen while retaining authenticated
  state, nonzero magnitude, zero secret/tag, sequence/epoch successor, and underflow checks. The
  root replayed 11 KAT/roundtrip/all-byte-mutation/arithmetic/atomicity tests and the kernel
  `no-default-features` check. The exact module SHA-256 is
  `a31c298b3d084d7dc672278090b2d8f959f85d8f7e8fbc3a5ba00c7db7b96529`; the
  machine-readable checkpoint is `.agent/hardening/stablecoin-transition-v3-20260822.json`.
  This is not a production relation: authenticated genesis/source/oracle/collateral/attestation/
  key-refresh writers, restart/reorg persistence, outer action-intent derivation, sign mapping,
  relation lowering, governance, QROM/ZK, and refinement are all false. Because the 143-byte source
  prefix is static, Mint eventually ages out; a source-refresh transition is a hard gate, not an
  optional follow-up. The low-nibble 16-slot allocation also needs a collision-free launch rule.
- [x] (2026-08-22) Replaced and independently replayed the rejected first stablecoin V3 snapshot.
  The frozen transition row/membership/public/witness widths are now 453/713/315/1240 bytes. It
  binds distinct issuer, policy-admin, oracle, attester, and locked-collateral commitments;
  collateral asset/decimals/scale; attestation presence/freshness/dispute; cumulative epoch mint,
  debt, sequence, and exact before/after roots. The source state machine supplies canonical
  genesis, refresh, policy-upgrade, rotation, retirement, and activation transitions. Genesis
  privately opens all five secrets in every one of sixteen slots and proves exact commitments and
  pairwise separation. Rotation opens every old/new role, changes exactly the selected subset,
  preserves the rest, and rechecks separation; every enabled update still requires the old admin,
  with its `auxiliary_authority_mask` naming only additional participants. The root independently
  replayed 12 transition tests, seven source tests, and the kernel no-default-features check at
  transition/source SHA-256 values `c533ff732b68b02a2ded89770f20385ad570ad7c5653f42580635d0fb50a4df9`
  and `53c7f957d8729a60be84e648e00bf49ac36c381554f1f496bdda011e5e4c1400`.
  `.agent/hardening/stablecoin-transition-v3-20260822.json` schema v2 records the superseding
  checkpoint. Typed public and witness ranges are the only downstream compiler authority. Root
  lifecycle, governance, transaction compilation, QROM, complete ZK, refinement, consensus route,
  and production authorization all remain false.
- [x] (2026-08-22) Resolve the exact theorem boundary for complete QROM zero knowledge. CMS19
  Theorem 8.6(3) does explicitly preserve statistical zero knowledge for salted BCS in the QROM;
  this corrects the narrower claim that CMS only transports soundness. The printed BCS16
  transformation nevertheless queries binary proof strings, so its literal instantiation at the
  provisional K=1024 geometry is tens of gigabytes and cannot be built under the disk gate. A
  field-word/alphabet-leaf encoding projects near 2.14 MB, and BCS16's Merkle privacy lemma itself
  accepts arbitrary leaf values, but Hegemon has not yet supplied the required word-local-view
  HVZK/alphabet refinement. A literal K=1024 beta=1 BCS screen is 56,844,329,600 proof bytes and
  16.206 TiB of bit-leaf tapes, so it is categorically disk-inadmissible; the approximately 2.14 MB
  vector-leaf figure is only an unproved projection. The smallest surviving ZK architecture applies
  the GHCM21 adaptive QROM reprogramming bound directly to SmallWood's 512-bit independent DECS
  leaf tapes, but only conditionally: with at most `2*N+8` programs, `N=2^20`, a global `2^64`
  QRO-query budget, and a `2^64`-proof history, 512 fresh entropy bits leave only about 138.4 bits
  before all other terms. Current V6's 32-byte first Fiat--Shamir salt supplies only 256
  theorem-obvious bits and yields roughly 96 bits at `q=2^64`; a fresh 64-byte salt or a proved
  conditional-root-entropy lemma is mandatory. The whole-protocol hybrid, every conditional
  min-entropy premise, exact program count/order, sampler/programming equivalence, multi-proof and
  grinding model, joint IOP/PCS HVZK, and concrete SHA-512/SHAKE-as-QRO bridge remain unproved.
  GHCM addresses ZK only: CMS/RBR soundness separately makes historical `q_D=23` nonviable, with
  provisional K=1024 screens requiring about `q_D=55` (beta=1) or `q_D=48` (beta=2) before final
  relation rows and every hidden constant and union term are known.
- [x] (2026-08-22) Retain and independently replay the corrected fail-closed composition ledger at
  `.agent/hardening/strict-odd-field-composition/ledger.json` (SHA-512
  `d5e07dc48505e19c5f18483a059a36043b8b109582a942bd103e223aa79f5e36bfd5b42503676134e11ee674b8a6bbf09567527b527c8d02a1b000ab79515436`).
  Its checker passes and all 32 arithmetic/structure/mutation tests pass. With conservative
  `R=2*N+8=2,097,160`, 512-bit conditional entropy yields exactly
  `3,145,740/2^160` after the retained history union (about 138.415 bits); 576 bits yields
  `3,145,740/2^192` (about 170.415 bits) only as a homogeneous all-program sensitivity. That is
  not the final direct-route bound: widening leaf tapes does not widen the eight transcript-chain
  program points. With `2*N` leaf programs at 576 bits and eight chain programs at 512 bits, the
  history terms are exactly `3/2^172` and `3/2^158`; their sum is `49155/2^172`, about
  `2^-156.4149494468487`, conditional
  on proving fresh 512-bit chain entropy at every stage. The ledger's historical 23-opening sensitivity is
  184 extra proof bytes for 72-byte tapes plus 32 bytes for a 64-byte salt. The selected sound
  profiles are now also priced exactly: 48 openings add 384 tape bytes/416 with the salt, while 55
  add 440/472. The overall advantage, concrete-hash QRO terms, CMS/RBR refinement, complete
  simulator, winner, proof measurement, and production profile remain JSON `null`/false.
  The arithmetic/obligation boundary is now mechanized in
  `formal/crypto/HegemonCrypto/SmallWoodGhcmQromZk.lean` (SHA-512
  `50ccefb2f5b598104ff5702dfda5cec55cb7ad7f1a5aa90614f23c7b7aa51d7d3fb2baaf5659559b411312d48d30312f6fa9cfb5ec0331e3148963ece983fb7f`).
  It proves the exact leaf `3/2^172`, chain `3/2^158`, heterogeneous `49155/2^172`, strict
  `2^-157 < loss < 2^-156`, h256 first-program `3/2^97` failure, h256-history `3/2^33`, and the
  non-authoritative homogeneous sensitivity `786435/2^190`. Twenty-five atomic external
  obligations are exhaustive and duplicate-free; their indexed evidence type has no constructors,
  the retained evidence is `none`, and Lean proves production prerequisites cannot be derived.
  Root independently replayed the 792-job targeted Lake build, forbidden-token scan, and axiom
  audit (only `propext`, `Classical.choice`, and `Quot.sound`). This closes arithmetic/reporting,
  not GHCM applicability, complete ZK, concrete SHA-512/SHAKE QRO security, or production.
- [x] (2026-08-22) Completed a read-only code-to-theorem audit of the reusable SmallWood engine and
  invalidated the first HX512 transcript freeze. The engine has credible component masking:
  five high coefficients for PIOP witness rows, uniform nonlinear masks, sum-zero linear masks,
  Equation-6 PCS randomizers, `q` independent LVCS tails, a real disjoint evaluation coset, eta
  DECS masks, index-bound leaves, compact paths, and canonical field/matrix parsing. It still has
  no retained simulator for the joint serialized view, no general conditioned rank/refinement
  proof, and no fresh HX proof/parser consumer. The active inner grammar remains SMZ1/SMZ2 with a
  32-byte salt, 64-byte tapes, and `q=23`; the outer HX wrapper's caller salt is independent and
  cannot repair that. The rejected first HX transcript also failed to consume sampler state and
  permitted duplicate stage/label challenge reuse. CMS19 soundness/RBR premises do not substitute
  for its Theorem 8.6(3) HVZK premise, while direct BCS16 Lemma 7.5 with SHA-512 is at best 126-bit
  statistical ZK even before other losses. The surviving route is conditional SmallWood Theorem
  10 with one prover-generated 64-byte salt and independent tapes, plus a separately proved
  adaptive GHCM/QROM lift and whole-view simulator. For prospective K=1024, R=11209, degree six,
  beta=2, rho=eta=5, the exact classical interactive floors are about 173.409 bits at q23 and
  257.049 bits at q48/q55; these omit Fiat--Shamir, hash, QROM, unions, ZK, and refinement. Under
  the obsolete inner serializer mechanically widened to 72-byte tapes, q48/full paths projects to
  1,819,683 bytes, not a measured proof. Production and the canonical byte count remain null.
- [x] (2026-08-22) Rejected the provisional q48/five-PIOP-opening strict profile before identity
  allocation. Its five-opening consistency term is about `2^-257.049404318`, but the exact CMS19
  envelope multiplies interactive error by `12*Q^2`; at the committed `Q=2^64` budget this term
  has only about 125.464442 bits, below the strict target before every other positive term. At the
  actual K=1024 packing factor, six openings change the consistency degree from 6168 to 6174 and
  raise the local post-CMS exponent to about 176.866605 bits, but require at least
  six matching witness-hiding high coefficients and a fresh degree, PCS, rank, serializer, and
  proof-size calculation. q48/s6 is therefore only the next provisional profile; no wire identity,
  measured bytes, or composed-security verdict exists yet.
- [x] (2026-08-23) Closed the first architecture tournament with no qualifying winner and selected
  the shortest credible implementation route: one Boolean-native M4 proof with true E384
  challenges and a mixed authenticated B128-coefficient-lane BaseFold PCS. Repeated B128 M4 is
  rejected despite its retained 1,344,828-byte artifact; it has the wrong relation, weak component
  security, incomplete joint ZK, and no direct-product QROM theorem. The E384 route is now being
  implemented but remains a candidate until its real PCS, complete-ZK simulator, composed ledger,
  exact parser, and retained artifact all pass.
- [x] (2026-08-23) Re-ran the opening-layer tournament after the complete-ZK counterexample. The
  retained 4+3-tree E384 BaseFold serializer projects to 1,528,928 bytes at the incomplete q310
  scaffold before ZK, while q116 projects to 695,840 bytes only as weak historical evidence.
  Diamond ePrint 2025/1015 Construction 4.1 schedules the source-faithful BaseFold repair at
  `ell+1` with `kappa = gamma * 2^vartheta` random coefficients, so the operative cost is relation
  dimension doubling rather than free n16 slack. BaseFold is therefore noncompetitive on present
  evidence. The next single falsifiable screen is one-level authenticated Ligerito/TensorSwitch
  with E384 algebra and SHA-512: its n16 serializers model 144,496 bytes with a 64-GiB oracle or
  168,688 bytes under a 512-MiB oracle bound. Both figures are unmeasured, non-ZK, omit the exact
  compiled relation and composed security, and confer no architecture leadership.
- [x] (2026-08-23) Independently executed the bounded source-faithful one-level Ligerito/E384 core.
  All 15 dependency-free field, transcript, parser, roundtrip, mutation, ledger, and fail-closed
  tests passed, and the pinned source checker passed. The optimistic source-128 fixed
  maximum-frontier grammar is exactly 136,048 bytes at `q=64` with a 2 MiB oracle; the conservative
  source-264 grammar is exactly 208,400 bytes at `q=132`. These are source-screen serializer
  results, not retained production-proof measurements or lower bounds: variable multiproofs may
  be smaller on particular query sets, while any complete-ZK wrapper and exact maximum Hegemon
  relation can only be priced after construction. `complete_zk=false` and
  `production_authorized=false` remain explicit.
- [x] (2026-08-22) Sealed the strict-QROM profile selection audit and kept the production profile
  null. Under the local exact-rational policy corollary only, the best one-level source-error
  screens are E384 at `q=130`, 206,992 bytes, about 128.507 conditional bits and E512 at `q=130`,
  232,768 bytes, about 128.598 conditional bits; `q=129` fails both. Equal source-error unions of
  2/8/16/64 terms require `q=131/132/132/133`, respectively. These wire figures include no ZK
  cost and do not instantiate a full IOP. More decisively, the direct BCS statistical-ZK theorem
  term at lambda 512 gives only 114/115 bits for the respective committed-unit floors; strict 128
  requires integer lambda 569/565, byte-aligned to 576/568, followed by fresh geometry. The exact
  IOP/RBR error, modified-BCS transcript and augmented query count, concrete SHA-512 QRO bridge,
  grinding, semantic-hash, multi-proof/action/consensus, and parser/refinement terms are all null.
  The independently rerun exact checker and 24-test mutation suite pass only with selected query,
  composed bound, strict-PQ authority, and production authorization null/false.
- [x] (2026-08-23) Advanced unkeyed RFC 7693 BLAKE2b-448 plus SHAKE256-448 against split SHA3-512,
  without authorizing either. BLAKE uses 15 hidden/preimage calls / 28 compressions plus 68
  collision calls / 105 Keccak permutations; every former 112-byte derivation is two same-length,
  separately tagged 56-byte calls. A source audit of the pinned builder corrected the gate model:
  each BLAKE compression emits 576 nonlinear AND constraints, while its 384 rotations are linear
  Shift constraints. The raw AND screens are therefore 79,128 for mixed BLAKE versus 90,600 for
  split SHA3, an 11,472-AND BLAKE lead, with 10,752 BLAKE rotation-linear constraints reported
  separately. This is not a total-row or proof-byte winner: addition-linear, XOR, mux,
  counter/final, Keccak-linear, DCE, and oracle-shape effects still require identical compiled
  geometry. BLAKE also remains conditional on an explicit concrete-hash-as-QRO assumption and
  honest 384-bit source refinement.
- [ ] Compile the exact conventional mixed-hash full relation into the tournament winner. Completed:
  the reusable executable
  Boolean compiler constrains FIPS-202 padding, all 24 Keccak rounds, 56/112-byte outputs, and
  exact per-bit source/target bindings. Both authorization slots now have one fixed two-block
  shape containing all five canonical mode arms, internal FIPS padding, Boolean one-hot selectors,
  and 2,176 selected absorption-bit mux constraints; the combined statement/SHAKE suite passes
  22/22. The canonical 893-byte statement and exact 79-call/124-permutation schedule are frozen
  rejected-candidate evidence. HGF6HR02's 79-call/145-permutation schedule is also rejected because
  its wide-capacity XOF is nonstandard. The surviving successors are mixed unkeyed
  BLAKE2b-448/SHAKE256-448 and split SHA3-512/SHAKE256-448; identical executable compilers are now
  being landed to decide them on compiled/DCE geometry rather than operation folklore. Remaining:
  freeze the smaller executable program and E384 backend together, allocate one fresh
  identity, and bind the exact emitted program/source digest rather than a descriptor projection.
  The scalar compiler now evaluates the non-hash families as deterministic host semantics and
  emits executable Boolean hash traces; it is a differential oracle, not an R1CS or proof relation.
  Those checks must be revalidated by its certificate API and lowered independently into the
  tournament's Boolean-native winner; the executable serialization/source digest and qualifying
  backend remain absent.
  Production authorization remains an unconditional error.
  A 2026-08-23 source checkpoint found that the fresh `full_blake2b448_relation` module still
  ended after its registry, authority wrapper, error enum, and fail-closed gate; it did not yet
  implement the advertised canonical frame compiler, hash constraints, fixed mux, non-hash
  relation, or corpus. Its enabled-stablecoin wrapper also required nonzero version and three
  authority digests, which strengthens and therefore fails to refine the exact source relation.
  That checkpoint is not credited as an executable successor; the worker must remove the semantic
  divergence and land the complete dual-profile compiler before this item advances.
  A later checkpoint superseded that skeleton finding: the scalar module now implements the fresh
  893-byte codec, exact 83-call dual-profile schedule, typed frame sources, Boolean BLAKE/SHA3/SHAKE
  traces, fixed authorization muxes, a shared host-semantic certificate, KATs, and fail-closed
  machine flags. Its current verifier independently redecodes and losslessly reconstructs the
  statement, rederives all frames/source maps/internal chains and non-hash semantics, and checks the
  exact per-index call specs. This is still a differential scalar oracle, not one aggregate proof
  constraint/equality graph. Its ignored disk-gated corpus covers both profiles across the 33 valid
  mask/mode pairs plus rejection, balance, stablecoin, inactive-padding, and retained-object
  mutations; none of those 66 honest compilations has run.
  The M4 source has also reached a statically closed checkpoint: all 83 indices pass exactly once
  through a typed lowering audit with exact or five-arm frame width, algorithm, role, primitive-core
  count, and output-binding metadata; direct relation-body hash calls are checker-banned. Local-only
  dependency pinning, `rustfmt --check`, `git diff --check`, and `python3 check_source.py` pass. This
  is not compiled/DCE or differential-parity evidence. The aggregate artifact flag, stablecoin
  manifest adapter, E384 PCS, complete-ZK, QROM, identity, winner, and production flags all remain
  false. In particular, call 74 is accumulator authorization policy rather than the active
  stablecoin policy identity, and the diagnostic's three opaque 56-byte values do not refine the
  live 48-byte manifest authority. No compiled/DCE credit is assigned yet.
  The frozen source SHA-512 is
  `f59b5e476295bd1bc2860c83e767a90ce1e028368c2434872d87b47c34fba1eea9ef9ceda96683e5d587aa3d2dee95f4d0a7d951833d1635183609a5305e11df`;
  its ignored corpus now contains 33 accepted and 47 rejected mask/mode cases per profile. An
  independent static parity audit found no frame/spec/core/output-binding or shared-wire mismatch,
  but also confirmed there is no retained Cargo lock/build identity and the diagnostic source
  digest concatenates included files without path/length framing. Both must be replaced by a
  canonical framed build/source manifest before any release identity is allocated.
  The pinned `binius64` dependency is additionally a repository symlink into the 13-MiB transient
  `/private/tmp/hegemon-strict-full-baseline-binius` tree at upstream revision
  `3f96163049f680b2909f6545690bd929f1b48c44`, with 31 modified files and one untracked grouped
  sumcheck source. The 688-file digest binds the selected inventory bytes but does not retain that
  dirty tree or make the candidate self-contained. A winner must vendor the exact reviewed source
  and licenses or reproduce the complete patch set from a clean immutable base before type-check,
  proof measurement, and release evidence can qualify.
  The latest checkpoint supersedes every `HX448C01`/893-byte live-diagnostic statement above.
  Fresh test-only `HX448C02` grammar 2 is exactly 869 bytes, 125 seven-byte scalar limbs, and 109
  eight-byte M4 words. Non-stablecoin semantic digests remain 56 bytes; policy, oracle, and
  attestation are three direct 48-byte fields, decoded as six little-endian M4 words each without
  padding, truncation, or reinterpretation. The scalar retains a whole externally supplied
  `ProtocolManifest` plus current height, mirrors native existential plausible-entry selection,
  reruns lifecycle/freshness/dispute/issuance/cap predicates, and independently derives the exact
  61-byte SCALE/RFC 7693 BLAKE2b-384 policy KAT
  `4e36d2e5728b9b3a1eb473aac318800434bf3947817410a281d04e8ea6b68ed133bc48c3570db5c3935126aa76be2100`.
  The source checker, `rustfmt --check`, scoped `git diff --check`, independent layout/packing/KAT,
  and a 33-node/114-edge zero-cycle local dependency scan pass. Post-format SHA-512 pins are scalar
  `b029ebec35c9d001d245b843a7ae918a2578ec961f7b0bd6097eb28950644ab2c2a9d9bfc58d87db39ad225b940347eaaaf3f678c3462663d07c3b5c59f0ceab`
  and M4
  `1cf8ca5c3b5202cadc8bfe2b075a0a844f31f69ba4ebc646dde672cca94dc72c50c22c856ce3763939d0005f7c90968b5ac56385174d36cfeb99d46ad6495a14`.
  This is source-static compatibility relative to a caller-supplied manifest, not aggregate parity,
  compiled relation geometry, or consensus-state authority. The current kernel root excludes
  stablecoin policies, the source manifest has no active policy, and all production/security flags
  remain false. Cargo/rustc/proof execution remains blocked by the disk gate.
- [x] (2026-08-23) Sealed the source-only `HX448C02` scalar-to-M4 parity certificate without
  claiming execution. The checker independently passes 83 typed calls, 11 frame layouts, 99 frame
  nodes / 18,695 bytes, 22 non-hash groups / 170 named source edges, the exact 33-accept/47-reject
  mask-mode partition per profile, the 61-byte policy KAT, and the pinned 688-file Binius source
  tree. All 19 fail-closed mutations pass. The framed source, Rust source, BLAKE-program, SHA3-
  program, and evidence SHA-512 values are retained in
  `.agent/hardening/scalar-m4-parity-certificate/certificate.json`; every compiled/executed counter
  is exactly zero and `executed_scalar_m4_parity`, strict stablecoin PQ, winner, identity, aggregate
  artifact, and production authority remain false. Exact ignored Cargo commands are retained in
  `corpus.json` for execution only after the 28-GiB disk gate opens.
- [x] (2026-08-23) Sealed the role-by-role conventional-hash and LaZer QROM escape audit. The first
  byte-aligned idealized collision width is 400 bits. The compatibility-preserving SHA-512-left400
  experiment is 953 statement bytes / 137 limbs, costs 204 compressions before the three stablecoin
  constructors, and needs 512 bytes of secret material; its exact low-budget semantic slice is
  `648*(2^64+1)^3/2^400 + 15/2^159`. That expression assumes concrete tagged SHA-512 is a QRO and is
  not a deployed-hash theorem or full proof composition. HMAC-SHA-512, SHA3/SHAKE, KMAC/TupleHash,
  and BLAKE2b-400 likewise lack the required concrete bridge. LaZer Pack starts at 125.678 bits and
  even the favorable DFM20 screen requires `lambda >= 261` and combined challenge width `>=260`
  before the absent quantum interactive-PoK premise. The full dependency-free suite passes 55/55,
  source binding is true, both CLIs emit valid-negative status/exit 2, and every capability remains
  false.
- [x] (2026-08-22) Disqualified the retained M4/BaseFold hiding topology independently of field
  width. Its committed leaf is the interleaved pair `RS(message), RS(mask)`, and the query opening
  serializes both scalars. Conditioned on the same opened coordinate, two valid witnesses for one
  public statement can therefore have disjoint message supports and total-variation distance one;
  SHA-512 tapes, E384, and E512 do not repair that view. The sealed exhaustive audit reproduces
  conditional TV `1`, the public-only simulator lower bound `1/2`, and the exact depth-20 hit
  probability `319/2^20`; opening only a single masked share is the expected TV-zero negative
  control, while reopening the mask restores TV `1`. Exact source-screen CMS arithmetic is
  diagnostic only: with the retained `M=2^20`, `G=589824`, and `t=k=2^64`, query-only error first
  passes at `q=313`, a pessimistic twelve-term union at `q=317`, and the separate 264-bit-per-term
  policy at `q=318`. At the serialized `q=319` screen the E384 maximum-shape projection plus the
  named direct-mask floor is 1,579,520 bytes; E512 is not structurally needed and reaches
  1,804,384 bytes. There is no production `q` because the actual M4 error vector, RBR/special-
  soundness premise, and whole-view simulator are absent. The independently rerun 15-test audit,
  canonical certificate, repository-source contract, and pinned-Binius source contract pass with
  every capability false.
- [x] (2026-08-22) Re-screened CFW26 HVZK-WHIR and its merged Plonky3 implementation as the
  strongest complete-ZK topology, without selecting a winner. The paper gives composable HVZK and
  a relaxed round-by-round straightline knowledge notion; the latter implies the RBR soundness
  needed for the soundness clause of CMS modified BCS, but is explicitly weaker than CMS RBR
  knowledge. Its complete-ZK R1CS compiler requires odd characteristic. Plonky3 implements the
  hiding WHIR PCS only and explicitly leaves that R1CS reduction out of scope; its only published
  implementation numbers are weak 100-bit KoalaBear PCS data with about 120 KB fixed mask-opening
  overhead, not absolute transaction-proof bytes. The next bounded implementation screen is thus
  an exact odd-field Boolean/R1CS lowering of the frozen Hegemon relation into the implemented
  hiding PCS, with SHA-512/SHAKE authority and CMS clause-1/clause-3 composition. `winner=null` and
  all production capabilities remain false until that same-relation artifact exists.
  A later source check narrows the locally implementable field route: the pinned Plonky3 checkout
  implements two-adic Goldilocks binomial extensions only at degrees two and five, so its sole
  locally supported wide candidate is degree five (approximately 320 bits). There is no supported
  Goldilocks degree-six/E384 or degree-eight/E512 type to select by alias. The generic
  `HidingWhirPcs` and `StandardUniform` bounds do admit the degree-five type at source level, but
  `WhirConfig`'s `security_level` and grinding calculations are classical. E320 therefore remains
  only an API-feasible candidate until an external exact ledger pays the PCS/IOR, modified-BCS,
  Fiat--Shamir/QROM, SHA-512/SHAKE, grinding, union, parser, and consensus terms strictly below
  `2^-128`; no build or proof execution has occurred under the closed disk gate.
- [x] (2026-08-22) Independently cross-checked CFW26 Construction 11.4 and failed its printed
  R1CS-to-IOR bridge closed. Step 3 and Step 8's first equality use coefficient one on each inner
  mask, while Step 8's immediately displayed decomposition and the page-71 value-claim argument
  use coefficient two. Step 9 then supplies `(pow(alpha_i), ze(rho)_M)` to `sl_id`, although
  Definition 5.2's identity form accepts a single state; Definition 5.4's `x(sl_id)` is the typed
  scalar wrapper. Coefficient one plus `x(sl_id)` is an internally plausible repair, but no
  official erratum or revision authorizes it, and Plonky3 issue 1590 explicitly leaves Section 11
  out of scope. No production theorem bridge may select either repair. The reference implementation
  screen must execute the literal text and both candidate repairs only as diagnostics and keep the
  theorem/refinement capability false unless an authoritative correction or independent proof closes
  the ambiguity.
  The retained differential repair audit now sharpens that boundary. The literal coefficient-one
  plus printed-identity branch is ill-typed and its charitable first-component projection leaves
  residual `sum_M (1-z_M) S_M`, failing 289/384 seeded honest trials. Coefficient one plus
  Definition 5.4's `times(identity)` and a separately consistent coefficient-two/scaled branch
  each pass 384/384 local typing/completeness trials; exact `F_5` enumeration also gives the same
  witness-independent 125-point value-slice distribution for both nonzero coefficients. The lead
  independently reran 20 unit tests and the source/artifact checker successfully under artifact
  manifest SHA-512
  `fa6cede381a60323975cb66ae78855ca05d7edfd37492f957e21f70d3662442c88eab0772a718d9f7501e721f2ab8b9c7880763f17abf55c09c04eeaff4d5209`.
  This proves only a local typing, honest-completeness, and public value-slice lemma. Encodings,
  adaptive oracle hybrids, zero-evader error, RBR extraction, the outer transcript, whole-view
  HVZK, Fiat--Shamir/QROM, and implementation refinement remain unproved; all authority flags stay
  false while a complete parametric-repair proof is attempted.
- [x] (2026-08-22) Finalized an independent executable CFW26 Section-11 IOR diagnostic and kept it
  theorem-relative rather than promoting a locally repaired protocol. In addition to the mask-
  coefficient contradiction, the exact source typing audit finds two Step-9 defects: the inner
  identity form receives a pair instead of its required matrix state, and each main identity form
  receives an entire matrix description instead of the required `1 x ell` row fixed at `alpha`.
  Both coherent coefficient branches and both typed output encodings execute on the toy fixture,
  but the printed relation fails closed. The lead independently reran the retained checker after
  repairing a stale JSON-canonicalization race: 27 tests and 56 mutations pass under certificate
  SHA-512
  `3ce57f71ea09b564ecc9ca0ad3f54d6b2e341aba057ef737bfa58ebb74793cc6535f089fa3212f9776d39333a36ce2caa9fa6cf717ecd04990117687f8fc011f`.
  For the exact Hegemon source geometry the arithmetic projection is `ell=2^25`, carrier side
  `2^26`, 26 sumcheck variables, and 105 encoded-oracle hybrids. The expanded carrier, parser
  refinement, PCS mapping, whole-view simulator, RBR theorem, QROM composition, and proof bytes
  remain absent; every production/security authority flag is false.
- [x] (2026-08-22) Completed and independently replayed the full parametric theorem-delta for a
  repaired CFW26 Section-11 relation. A new construction with public `c=1`, coefficient-vector
  endpoint states `(pow(0),pow(1))`, `times(identity)` inner forms, and typed
  `row_M(M,alpha)` main forms has a direct perfect-completeness proof, a uniform value-slice
  lemma, and the required odd-characteristic outer-transcript affine bijection. It does not
  inherit Theorem 11.3. The printed endpoint state rejects the valid mask `X^2-X`; the printed
  first RBR numerator is falsified by an explicit sparse invalid `F_101` R1CS whose downstream
  target relation accepts with probability `1-(100/101)^11`, about `0.103676`, exceeding
  `9/101`; and an injective `F_11` encoding witnesses that fixed-set ZK does not imply adaptive
  query ZK (maximum two-fixed-query distance `2/11`, adaptive distance one). The repaired whole-
  view claim therefore closes only conditionally for Definition 4.7's nonadaptive class and
  assumed zero-knowledge encodings, with 105 hybrids at Hegemon's `d=26`. Full RBR extraction,
  adaptive complete ZK, Fiat--Shamir/QROM, PQ128 composition, implementation refinement, and
  production authority remain false. The lead reran all 22 tests and the fail-closed checker;
  canonical artifact-manifest SHA-512 is
  `848dde2ce910a64fa6125072912d973e8070d84f961b78d9352fc823c66e851f8bffa5e5d9a58e631b409163f3fe01fc462d2c96a1806a5f99052bdefb8897e7`.
- [x] (2026-08-22) Instantiated the printed CFW26 non-succinct code/profile far enough to obtain an
  exact size disqualification rather than extrapolating from the communication theorem. Plain
  Reed--Solomon E320 encoding gives one main, 78 inner-mask, and 26 outer-mask oracles, plus the
  105 second-layer Construction-7.2 oracles. Exact interactive communication is 168,040,165 field
  elements, 53,772,852,800 bits, or 6,721,606,600 bytes. The BCS direct statistical-ZK term first
  passes at byte-aligned lambda 664 (83-byte digest, 166-byte salt); lambda 660 fails. A literal
  theorem-faithful 30-round bit-leaf wire then projects to 32,252,325,377,789 bytes, while even an
  explicitly non-theorem field-symbol batching sensitivity is 1,458,868,874 bytes. Neither is a
  proof measurement and canonical `proof_bytes` remains null. The local Section-11 repair theorem,
  MCA bounds, CMS/QROM lifting, concrete SHAKE instantiation, verifier refinement, and production
  authority all remain absent. The lead reran the checker, all 9 unit tests, 20 mutation rejections,
  and whitespace checks; profile SHA-512 is
  `6cdca694581b4bc170a0c1c1876e09995713c7cb6c61b6c99f501f831c7e4469ae871a5dfd17c6f4a512f957aad695502d2a74b6d17a7295294a7668a334d80b`.
  This theorem-faithful CFW lane is size-disqualified.
- [x] (2026-08-22) Sealed a bounded HVZK-WHIR outer-wire source profile without promoting it to a
  proof system. The canonical parser, SHAKE256-512 transcript/MMCS roles, exact-consumption grammar,
  34 structural mutations, one transcript-changing payload mutation, 1,227 truncation/generated
  parser cases, and 13 unit tests pass under profile digest
  `a505fee2df5c4b81f80f45cc04d75b6588581bf3a3a4ec9d1dcac2da1e297fd40637c202180203dada7ea57d73ec4d78fa977d895cf3988a0ece2ad9a6744f78`.
  The locally available later Plonky3 checkout matches seven pinned source hashes and contains no
  Section 11 R1CS adapter. The retained 459-byte object is explicitly an invalid parser fixture;
  `proof_bytes=null`, all 20 composition terms are missing, `winner=null`, and production remains
  false.
- [x] (2026-08-22) Source-sealed the `HX448C02` non-hash and consensus-state lowering without
  claiming an aggregate proof. The dependency-free checker independently reports 109 statement
  words plus 50 consensus-state words, 20 local non-hash groups, 7 transaction hash-link groups,
  and 9 consensus-state groups. The graph now constrains all 16 masks, all five authorization
  modes, ranges, signed/native and non-native balance, mint/burn, selectors, inactive zeros,
  Merkle/hash links, equal nonzero expected/provided manifest commitments, equal expected/provided
  height, selected-policy fields, lifecycle, freshness, dispute, and the full `u128` issuance cap.
  Sixteen counterfeit mutations are assigned to M4 rejection. Four more are deliberately
  host-only: whole-manifest BLAKE2b-384 recomputation, selected-entry membership, policy-identity
  recomputation, and consensus authentication of the expected commitment/height. The inactive
  kernel commitment seam binds all 14 ordered policy fields in 183 bytes under RFC 7693
  BLAKE2b-384; its 48-byte KAT is
  `c7101239692a8743b4f55073f16eddd3c54f3618f79d78ede2b4a2469d0fea6fa16503bf6f74cc3ae53d6f674d9b27a1`.
  It is not included in `kernel_global_root`, and production remains false.
- [x] (2026-08-22) Lowered that frozen source schedule into a deterministic odd-field macro-R1CS
  screen without claiming a proof. The exact grammar has 10,152 public bits (869-byte statement
  plus 50 consensus-state words) and 77,376 private transport bits (1,209 words). All 20 local,
  7 hash-link, and 9 state-seam families are nonempty; the 80 mask/mode pairs split exactly into
  33 valid and 47 invalid shapes. The smaller mixed BLAKE2b-448/SHAKE profile has
  `m=20,457,227`, `n=19,311,555`, `l=10,152`, and 94,551,238 sparse-matrix nonzeros, versus
  `m=23,727,052`, `n=23,613,572`, and 112,255,042 nonzeros for the split SHA3-512 control. A
  literal Section-11 equal-half embedding requires `ell=2^25` and a `2*ell=2^26` padded carrier.
  The lead independently reran the canonical checker and all 15 tests; 16 compiled mutations
  reject and the four host-only forgeries remain explicitly indistinguishable. Retained manifest
  SHA-512 is
  `dae278e46a5d2ed2c58fae4443db8b73967f2b1190336520081a6f3791c04fad63d182cc61c0e1fb75f66bdb70e9ff40d4b1b975d9295fcf3a93bf189c76607e`.
  No expanded matrix, PCS adapter, proof, measured bytes, compiler refinement, complete-ZK proof,
  QROM composition, successor identity, or production authority exists; this is a source-only
  negative baseline for the manifest-closure and hiding-WHIR work.
- [x] (2026-08-22) Disqualified ProveKit stable `v1.0.0` as a production challenger without using
  its unrelated examples as size evidence. The pinned release has a substantive generic sparse-
  R1CS/Spartan/two-zkWHIR stack, but no exact `HX448C02` relation, whole-view simulator theorem,
  finite-QROM composition, canonical bounded consensus parser, Hegemon lifecycle binding, or
  same-relation artifact. Its SHA-256/SHA3-256 binding surfaces have a generic quantum collision
  ceiling of `256/3`, about 85.33 bits, and its SHA-256 Spongefish bridge is explicitly heuristic;
  therefore `composed_security_bits=null`, `same_hx448c02_proof_bytes=null`, `winner=null`, and
  production remains false. The lead independently reran the dependency-free offline checker;
  report, ledger, and checker SHA-256 values are respectively
  `f1f211411912e2d05259559859f6ed9def435ac6e0682b16eaa93168dce18d4d`,
  `8236669f198f8259538941b57ecd60d9e5a7296eb56fb92037f71100ac358f28`, and
  `5a2c684b300c523ea0087cd2ac19c74123436b7963d0f734cdba2f0379e3bc5b`.
- [x] (2026-08-22) Defined and independently checked the exact sparse equal-half Section-11 map
  for the frozen negative baseline, without mistaking a compact descriptor for an expanded
  carrier. The map preserves every source A/B/C row, column, and coefficient, fixes 33,544,279
  public zeros, constrains 14,253,029 existential witness zeros with 28,506,058 nonzeros, and
  leaves 32,398,608 canonical zero rows; total carrier nonzeros are 123,057,296. The lead reran
  24 tests and 13 retained mutations successfully. Carrier-manifest SHAKE256-512 is
  `9ca447bdb81aa3b90edb1ed60a3b0cf7aa79d93d50dbb90466d93ad114585a3d509c61860e2a03b9c462965f2f30bec7f1af635f2f308e11236f629e51482925`.
  The source macro artifact still lacks its expanded coordinate stream and four predicates, so
  macro refinement, parser-padding refinement, PCS mapping, and production authority remain
  false. The compiler is parameterized for the successor geometry and explicitly invalidates
  this retained certificate when the all-W64/HX512 relation digest changes.
- [x] (2026-08-22) Sealed the strict odd-field composition ledger as a valid negative rather than
  assigning missing reductions value zero. CFW26 Theorem 11.3's minimum E320 communication is
  already 33,555,190 field elements, or 10,737,660,800 bits, before real code expansion. The
  BCS statistical-ZK loss `p*2^(-lambda/4+2)` is therefore about `2^-92.68` at `lambda=512`;
  byte-aligned 648 still fails and 656 only passes this lower-bound term, while exact codeword
  lengths and the required lambda remain null. The current semantic ideal-QRO lane separately
  fails at `2^-127` and `2^-126`; the theorem-only deployed-hash lane is unbounded and every
  explicit `Adv_QRO-inst(...)` value remains null. The lead reran the checker and all 26 tests;
  canonical ledger SHA-512 is
  `881bafb101fc4f4c9e9c95612e5ec4914432b8ae34023b5aa2c84e4fb7eb03a6fa892ab40d3e99584ab0bfaa5c2e04ee7af28aaf2ff4e0173fbe54e61ad70f13`.
  E320 retains only local field-arithmetic headroom; there is still no selected architecture,
  composed advantage, proof size, or production authorization.
- [x] (2026-08-22) Completed and independently replayed the bounded Ligero-family backup screen.
  Original Ligero has the closest theorem shape in that lane: its interactive construction has an
  explicit identical-view simulator and a protocol-specific round-by-round analysis. It still has
  no exact Hegemon compiler/refinement, exact modified-BCS finite-QROM instantiation, conventional
  deployed-hash reduction, canonical wire, or retained same-relation proof. For the older frozen
  odd-field relation, the exact source-264/640-bit evaluation of the paper's Section 5.3 expression
  is 16,437,920 bytes, but this is only an arithmetic receipt and is neither a proof measurement nor
  a bound. Even its optimistic 126,552,960-bit IOP-proof floor leaves the BCS statistical-ZK term
  at about 99.08 bits for lambda 512; lambda 632 only clears that floor in isolation. BooLigero
  changes the relation field, Ligerito is not a complete-ZK proof system, Flock explicitly lacks
  zero knowledge, and Ligero++ lacked a pinned complete primary construction in this bounded lane.
  The lead reran the fail-closed checker, all 15 tests, the local-PDF pins, and whitespace checks;
  ledger SHA-512 is
  `87f16345d43915c90cc8d64229fb26b7a5a5ffa571ebe00f21c89bd3bedd82243844f75741d58f0b53bfdf5b4f78741d5001730628319a45b56f33e48070b6c9`.
  Winner and all proof-byte fields remain null and production remains false.
- [x] (2026-08-22) Froze and independently replayed the source-only HX512 semantic suite that the
  final relation compilers must consume. The one accepted composite schedule is 83 counted
  `HX512B01` core calls plus the byte-for-byte specialized personalized all-W64 manifest authority;
  the alternate generic authority frame is rejected. RFC 7693 BLAKE2b-512 projects to 90 physical
  calls, 213 compressions, and 29,509,133 macro-R1CS rows, versus 36,867,121 rows for the split
  SHA-512/SHAKE256-512 control. The statement is 1,141 bytes, the private transport is 11,000 bytes,
  and the manifest membership is 475 semantic bytes. This is source-static geometry, not compiled
  Aurora/PCS geometry or a proof-size result. The theorem-only concrete-hash ledger remains
  unbounded; a separate conditional semantic slice reports about 154.913 bits only after assigning
  explicit nonzero hash-as-QRO assumptions. PCS, IOP, Fiat--Shamir, complete-ZK, selective-opening,
  parser/refinement, and release terms remain absent. The lead reran the checker and all 21 tests;
  suite-report and ledger SHA-512 values are
  `ca6b54182f987b94bcd961b205adebabcbdc16875877aab22e7fb5364529b66aff4eb1bbb826618ae7b883bb0992a86e732012daad27e1ca1f613d61573be0ee`
  and
  `2b988530dd42d8f32cf6c4e2102d04b30700654720917ef668168d7874de4b76df4b545942a88aff442fbc06e3c2e76692795f449ab9499980cf5b14de5d2d1e`.
  Exact full-relation compilation, proof bytes, composed security, winner, and production authority
  remain false or null.
- [x] (2026-08-22) Froze and independently replayed a new current semantic-only HX512 registry
  baseline against the corrected stablecoin V3 checkpoint. The canonical
  statement/verifier-context/private-witness widths are 983/136/11760 bytes. Five authorization
  modes crossed with all sixteen masks accept exactly 26 pairs and reject 54. Ninety-five typed
  RFC 7693 BLAKE2b-512 slots cost at most 226 compressions; the active disabled/mint/burn schedules
  are respectively 83/206, 95/226, and 93/222 calls/compressions. Typed stable public/witness ranges
  and row-prefix offsets are imported from the kernel with compile-time contiguity/width assertions,
  and the nonzero row/path/issuer KAT replays calls 83--94 against the kernel oracle. The independent
  isolated harness passed 13/13 tests: every one of the 26 accepted pairs has a retained distinct
  fixture KAT, exact byte roundtrip, full 95-slot recursive replay, and active-target checks; full
  Mint and Burn materialization additionally reject forged intent and after-row mutations. Whole,
  production-prefix (first 131199 bytes), and test-suffix SHA-512 values are respectively
  `e9cdaa4adcdd21427a61b566e0f8ac3d1dcd750a9d92e630cf935d298e9e4460ee87bb473cd94fcd3bc647c93117093430657b416ac510c6c8a28075c7a1d8bf`,
  `88631549e18d726663d0ba664a2b57184d3f93438e3dd6f01973d64051c4aabdf0cb16f514fe04d4ba642f5ef0d8c75e6e749a8a50c9e6b93b0e170f38fdce6a`,
  and
  `4cbfafc0652034d8e77bf97175dc59cdb369e4b2fc2e3fb173ebf76522fc3614d98ad5cfb03baab8ff89a6a572207f5cdcbe7372f57106f1299c7d22abe32a71`.
  No pre-fixture byte snapshot exists, so equality between the previously recorded whole-file hash
  and today's production prefix is not claimed; today's independently checked prefix is the new
  freeze. Counterfeit additions are one critical mutation per non-Single mode at mask 0x0f and two
  per stable direction, not exhaustive per-field negatives across all fixtures. The registry binds
  no proof parameter, so it cannot freeze the rejected s5 profile. Executable compiler, verifier
  refinement, complete ZK, composed PQ/QROM, consensus, and production authority remain false.
- [x] (2026-08-22) Superseded that source pin with the post-fixture evidence boundary, again as a
  new current freeze rather than an old-prefix-equality claim. The off-by-default
  `hx512-refinement-evidence` feature exposes exactly 30 grammar-owned debug fixtures ordered as
  five authorization modes x Disabled/Mint/Burn x two distinct private witnesses. Every fixture is
  materialized and label-checked by the production grammar; raw triples are unique. Non-debug
  builds with the feature fail at compile time, and debug admission returns a dedicated hard error.
  Default production semantics and every authority flag remain false. The whole relation source,
  first 133958-byte pre-evidence-module prefix, evidence/test suffix, and Cargo-manifest SHA-512
  values are respectively
  `e58ec353612262eb419cc4343d6a72c459d5963616fdd0b52f0619a80afc5eb525552417599f75bea892392a682c6d61839d37e9aba0a9cb864dc190807d986c`,
  `b9614b6a9829432dc5e74ff8047d31f3c77131d79e503165d1bd5272ff5aa7d95ffac68005e6b2d2eff27204229cbf3007be83b3152c2a0758e8b10b59f90f6d`,
  `ce6d712704e1883b4d68d3c66a2050d05f0fbe8523e8e5547ccfaa1c693a8367449d9f2d7c5f1e4acad6961c4630620277b4b2efb2fbc8ef1166e24435094ccf`,
  and
  `801047eae737ada473fb19248283a125f3ce86dc3b0745521fc3cfc60918193fc2a679e0a992b621b289ea27f901c65388df8803af2bd5e52a65947d76b628c8`.
  Adapter consumption and live 30-case replay remain pending at this checkpoint.
- [x] (2026-08-22) Froze and independently replayed the semantic registry's secret-independent
  radix-4/K=1024 hash topology. It contains 95 calls, 226 compressions, 103032 source bits, 51
  source rows, 113 message rows, 11728 core rows, 11892 total hash-base rows, 12177408 cells, 2500
  explicit padding cells, and 285744 typed operations. The exact RFC zero-padding bytes by the five
  authorization modes are `[8748,8494,8240,8570,8316]`. Root rebuilt an isolated harness against
  the current grammar and reran all ten topology tests, including all 16 masks x five modes x three
  stable directions. Source SHA-512 is
  `a4b7c3e5fcbe43aeac37abf268bdfd7e736ea3e0dcba935595518c3bcbc16b329f6831fc97e92cb36fc2e6c27439b09d49c0ccc052f2968d6fa24afb2897a9a0`;
  the test-only identity digest is
  `9f86ae65cfc4ad7208597595fac33adbf089ef0be5c42180f8f7c9dc0d16c25fae59a5a4ddd0d37bc20d0a59848a2e19392914a65b7fb51d69fdf39c8dba3a95`.
  `.agent/hardening/hx512-topology-20260822.json` records the boundary. The 11892 rows cover only
  the hash topology, not the complete non-hash relation; production identity/digest, final relation
  rows, executable topology-to-adapter refinement, proof profile, ZK, PQ/QROM, and production are
  null or false.
- [x] (2026-08-22) Replaced the invalid first HX512 transcript draft and independently certified
  the bounded inactive transcript/wire primitive. The quiescent,
  typed, exactly eight-event SHA-512/SHAKE256 candidate has source SHA-512
  `a33f9c8962ab6127ccc6866bafe1166186d4a3875843d55b7ac612b62e7ae5154726696ad35725f1d5eab22d53a343a9796de11b70fafce8f958b27846742b7c`.
  Its isolated dependency-free harness passes 9/9. Root and the disjoint auditor independently ran
  the post-source binary, SHA-512
  `c5ab9f1f85f8c0d1b9bfabb6a70298d1f36b610baca2e8a1756ce457aff4c3e9f3039b0b79fa2010b015849a18b7de41a18fefaacca8988856f957d731b5e2c2`;
  the auditor separately reconstructed the schedule KAT and rejected all 64 event-index-byte and all
  eight schedule-ordinal mutations. It consumes each stage once, poisons
  an in-progress challenge, returns the eighth event without a ninth hash, binds the exact 983-byte
  statement, 136-byte verifier context, one 64-byte salt, and a 422-byte profile descriptor, and
  deterministically derives and verifies the same disjoint radix-2 coset as the engine. It
  hard-rejects any packing factor other than 1024 or PIOP opening count other than six, and all
  security/release capabilities remain false. Checked wide multiplication and pre-conversion bounds
  now replace the rejected first draft's unchecked `usize` products. A subsequent audit also
  rejected two intermediate repairs because event one incorrectly sampled
  `eta * polynomial_count`; the engine actually samples `eta * lvcs_rows`. The corrected q48/s6
  fixture samples exactly 10300 DECS coefficients and 59500 PIOP coefficients and has regenerated
  field, query, and terminal KATs. Exact source comparison certifies e0 N/root, e1
  `eta * nb_lvcs_rows`, canonical e2 PIOP input, e3
  `rho * max(constraint_count, linear_constraint_count)`, canonical e4 PIOP transcript, e5 s=6,
  canonical e6 DECS opening, and e7 q48 distinct indices over N=2^20. This checkpoint certifies only
  the inactive module contract. Canonical engine reconstruction/refinement, deferred-claim QROM,
  complete ZK/PQ128, inner/outer integration, and production authority remain explicitly false.
- [x] (2026-08-22) Corrected the prospective SmallWood soundness screen against Theorem 1 /
  Equation (14). The engine's uniform-challenge branch had removed the theorem's
  `binom(N,d_DECS+2)` support-union penalty and credited only `|F|^-eta`; no retained extractor
  theorem or Rust refinement supports that strengthening. For the frozen q48/s6 fixture,
  `N=1048576`, `L=5970`, `d_DECS=6017`, and `eta=5`, the published epsilon-one term is vacuous.
  Exact integer arithmetic shows that this term alone, after `12*(2^64)^2` CMS amplification,
  first becomes strictly smaller than `2^-128` at `eta=840`, which adds 40,200,240 serialized
  bytes through `(eta-5)*(L+48)*8`. The actual post-adapter geometry is not frozen, so this number
  is retained only as a disqualifying fixture sensitivity. The fresh engine now exposes an
  explicit false soundness-authority flag; q48/s6 and every dependent wire/size projection remain
  inactive while the architecture tournament recomputes paper-valid profiles.
- [ ] (2026-08-22) Bind the fresh engine verifier to that exact eight-stage schedule without a
  circular challenge shortcut. The generic SmallWood verifier currently samples PIOP openings
  from `h_piop` before it reconstructs the DECS root, PIOP input, and PIOP transcript that occupy
  transcript stages one through five. The fresh core wire carries `h_piop` but not the claimed
  DECS root or early PIOP-input chain value, and the outer verification hook receives only a
  statement-binding digest plus opaque proof bytes rather than a live transcript. A fresh-only
  repair must identify and canonically serialize the minimal early commitments, advance the state
  in exact order, and later reconstruct and byte-exactly compare every claimed value before
  acceptance. No out-of-order derivation, deferred unchecked claim, or relabeled legacy field is
  admissible; wire bytes and the security/refinement ledger must include the added fields.
- [x] (2026-08-22) Added and focused-tested a fail-closed HX512 complete-ZK audit module at
  SHA-512 `92a02fad6b339b5cb781ebd35197361e6c94ae9593b199b5d7fa542d8fc3cc3d7434591ce7fd2d45a6736f8c3b1f1df60e7879c5c4fdd0a4fff84d42078ac5eb`. Ten tests
  enumerate all 33 verifier-view fields, check exact local finite-field ranks for q48/s6, expose a
  witness-free classical-ROM candidate view, and retain every whole-view, joint-correlation,
  adaptive-QROM, concrete-hash, parser/compiler, lifecycle, and artifact obligation as a blocker.
  The source-faithful SmallWood third soundness term uses
  `falling(mpol_degree + K, s) / falling(p - K, s)`: for K=1024 and s=5 the raw degree is
  6168, its floor is about 257.049404 bits, and the isolated `12 Q^2` CMS loss leaves only about
  125.464442 bits, decisively
  rejecting s=5 before any other union term. Local ranks and a sampled candidate view are not a
  joint simulator, complete ZK, or production evidence; all corresponding flags remain false. Root
  reran the retained certificate readback checker, which passed with 33/33 fields while reporting
  `complete_zero_knowledge=false` and `production_authorized=false`. A later joint-view audit found
  that this checkpoint still lists a four-byte serialized PIOP nonce even though the fresh core
  requires an implicit all-zero nonce and does not serialize it. The fresh driver also cannot call
  the legacy nonce/opening sampler because `Hx512Candidate` has no such branch and would panic.
  Superseding certificate/wire accounting must remove those four bytes and bind stage-six openings
  directly to the typed transcript before this checkpoint can be used for exact proof sizing.
- [x] (2026-08-22) Retained and independently replayed a joint classical-ROM ZK closure gate under
  `.agent/hardening/hx512_joint_classical_rom_zk_v1/`. The source-bound checker validates the
  corrected fresh grammar (`root64 || h3 || h5`, u32-BE matrix/auth dimensions, u64-BE field cells,
  no nonce/mode/aux fields), all 33 view fields, exact component ranks
  `6/5151/2052/180/98880/12/28365`, field-sampler abort floors `5860/5861/8190`, q48 index-abort
  floor 7346, combined sampler floor 5859, and the isolated SmallWood Theorem-10 classical-ROM
  floor of 191 bits. Root reran the checker with pinned local papers and all eight mutation tests;
  they report `VALIDATED_FAIL_CLOSED`, while `--require-complete` exits blocked. The direct BCS16
  lambda-512 route is at most 126 bits for a nonempty proof and remains disqualified. This is an
  executable simulator specification and negative release gate, not complete ZK: joint affine
  receipts, PIOP/PCS/LVCS/DECS distribution refinement, lazy-Merkle programming, retry/API
  refinement, tagged-product-RO and adaptive FS/GHCM/QROM lifts, concrete-hash instantiation, and
  compiled prover/verifier/parser refinement all remain false. The earlier source certificate's
  nonce and legacy-width/endian inventory must be superseded before it can become size authority.
- [ ] (2026-08-22) Refine the frozen radix-4 topology into the executable adapter. Root replayed the
  independent gate and its six mutation tests: it currently rejects with eighteen blockers because
  the adapter still treats canonical call IDs as execution order, does not consume the topology
  operation/dependency/source/target streams, exports no immutable correspondence maps, and has no
  retained evidence. Root also rejected the gate's first future-positive schema because it trusted
  self-asserted bijection/disjointness booleans. The gate must remain unqualifiable until a separate
  replay harness enumerates concrete operation, cell, dependency, source, target, padding, constant,
  and non-hash-row records and its mutation tests drop, duplicate, and alter real records. The
  current adapter has removed its stale numeric-index path, emits public-target records, and lazily
  enumerates the 12177408 topology cells, but still exports only digest-level identity metadata:
  it lacks complete operands/polynomials, a semantic-linear iterator, typed provenance for folded
  constants, full non-hash ranges, and independent live replay. A further structural defect is that
  identity templates are grouped only by `(family, polynomial)`, so non-hash and later hash
  occurrences of the same template can cohabit a K=1024 row group. The adapter must add an explicit
  origin/partition tag and certificate ownership; `nonhash_first_wire` is not a substitute. The
  grammar must own an off-by-default, production-forbidden 30-case refinement fixture API covering
  five modes x three stable directions x two secrets, and the adapter/checker must consume it rather
  than duplicate semantic fixture construction.
- [ ] (2026-08-22) Replace the rejected HX512 macro inventory with an executable exact relation.
  Independent red-team found that the first draft represented constraints only as anonymous
  primitive names and counts: it allocated no variable identities, emitted no sparse rows, and its
  host reference verifier accepted mutations of core note, nullifier, Merkle, balance, and
  authorization witnesses. It therefore cannot establish `m`, `n`, `nnz`, satisfaction, or
  semantic refinement and must not be called a compiled full relation. The same audit found two
  source divergences: the draft encoded `snapshot64 || height` as verifier context although the
  inactive V2 Rust authority exposes `manifest_root64 || height`, and it rejected
  `policy_version = 0` although the Rust grammar accepts every `u32`. Repair now requires a
  deterministic variable allocator and executable sparse-row stream (or equivalently exact
  indexed row generator), an independent witness builder/evaluator, mutation rejection for every
  semantic family, and byte-for-byte refinement to the canonical V2 authority. The previously
  reported `29,509,133` odd-field rows remain a source-static cost projection only until that
  compiler exists; they must not be reused over characteristic two because the odd-field carry
  equations and parity-only one-hot sums lose information there.
- [x] (2026-08-22) Closed the manifest-membership design boundary and rejected the tempting
  56-byte minimum. The exact cap-16 Merkle route dominates the fixed-vector comparator. W56 is a
  cost baseline only and fails the conservative epoch composition at `2^-126`. The minimum width
  surviving that screen is a fresh all-W64 215-byte row with independently constructed 64-byte
  policy, oracle, and attestation identities: selected membership costs seven BLAKE2b-512
  compressions, a 475-byte semantic witness, 60 transport words, and 965,301 macro-R1CS rows.
  Every byte of the 183/199/215-byte grammars and all 16 paths is mutation-tested. The native
  verifier must compare the public root and height to authenticated parent state before proof
  verification; membership alone cannot authenticate them. The lead reran the checker and four
  tests. Cost/capability SHA-512 values are
  `d199125742082ad92973d81c4b970eef0f37e57d8e6f47716dd5bbacdbe9338183eb79056b5123f0a7fd527f512032d3af6444167df8571617825e601f483a4f`
  and
  `60b3933fc2b674aafbb4c1889d3dc438dceebd5216e82f7d311f80b04a00a6292d843f5d553fdc2a6b1b6308cb191e389992b5e3744b99f879cc63ddb272d312`.
  Fresh state-writer constructors, QRO instantiation, global-root migration, compiler refinement,
  proof evidence, and production authority remain false.
- [x] (2026-08-22) Ported that exact all-W64 authority into an inactive kernel seam without
  changing the live root, genesis, registry, admission, or routing. The Rust module implements the
  215-byte row, 216-byte slot, cap-16/depth-four tree, 475-byte witness, 72-byte public parent-state
  suffix, strict ordering/prefix grammar, personalized RFC 7693 BLAKE2b-512 constructors, exact
  membership, typed parent root/height/snapshot comparison, lifecycle/freshness/dispute/nonzero/cap
  checks, and no 48/56-byte conversion API. All twelve activation and assurance constants remain
  false. The lead independently ran the source checker and seven adversarial checker tests, all
  sixteen paths, 215 row-byte/256 path-byte/154 constructor-byte mutations, the frozen four-test
  authority suite, and whitespace checks. Module SHA-512 is
  `99268907680ebff599f992e64f15cc9730f451eebd08b6e92776e66ee9afe567d6bf19eb1c1ff2482a3ea4a737a43e941cd04b7cb18f8e533239abdd474d395f`.
  Cargo/rustc execution remains deliberately unrun under the closed disk gate, so compiled runtime
  and native-refinement credit remain false.
- [x] (2026-08-22) Completed and independently replayed the MiTH/VOLEitH backup screen. QuickSilver's
  ideal-VOLE online correction vector alone is at least 163,657,816 bytes for the older relation.
  The pinned large-odd-field VOLE-in-the-head 128-bit source profile projects exactly to
  490,973,448 payload bytes before startup, framing, and the all-W64 growth; this is a source-profile
  arithmetic projection, not a proof measurement or universal lower bound. Direct ZKBoo-style
  arithmetic views are still larger. More decisively, the applicable generic theorems do not give
  an exact finite-QROM complete-ZK NIZK for this relation; the FAEST QROM result is signature- and
  relation-specific. The lead reran the exact source-pin checker, all 12 tests, 38 mutation
  rejections, and whitespace checks. Certificate SHA-256 is
  `1cb1e96a9192403286fd718300f62d3468ae6e1c798149f80963d7790853c7d3`.
  No MiTH/VOLEitH candidate is admitted and all authority remains false.
- [x] (2026-08-22) Hardened the inactive lifecycle seam without connecting it to production. The
  exact inline ciphertext bytes are now related to their stated hashes; expected network, chain,
  genesis, and rules context is checked at each decode; a distinct prospective action identity
  rejects every live 48-byte alias; and the restarted durable object is the sole input to the
  mempool--mining--block--sync--reorg--fresh-node chain. The dependency-free source gate and all
  16 tests cover 16 masks times five opaque authorization-mode tags and proof-byte equality at
  every modeled stage. Report SHA-512 is
  `db8da05ff44dcc4ed668b9ce1249bb8e99454d2357fc5d7d39a6bdc592164458f68cc3999d7b0aac2ddbea55a95b5d7a28746ca03cc769a4bc69c5c1efbc38cc`.
  This is still a source simulation: no Rust typecheck, real DB/network/miner/reorg process,
  verifier, stablecoin-W64 path, proof artifact, or release authority has run, and every route flag
  remains false.
- [x] (2026-08-22) Replaced that source-only lifecycle result with a compiled, retained, executable
  HX512 proof run. The optimized SmallWood prover emitted a 3,006,238-byte self-contained proof
  with SHA-512
  `abb8dee0d9f44c4f45efb09bb8615482b6cec9318252a51cf4ef282dcafb491ed5f547265ca3f6e8c8ea964a5ed7ecabd595c35cb9c41a102f1bbdb96065e2f1`.
  The runner verified it, rejected a proof-bit mutation, wrapped it into a 3,011,519-byte canonical
  inline action, rejected an action-proof mutation, read the retained files back, and reverified
  them. A second optimized runner decoded the same action through the wallet RPC/Base64 boundary,
  then exercised relay, mempool, sled flush/drop/reopen, restart, mining, block, sync, detach and
  reattach reorg, fresh-node, and import transitions while invoking the real verifier at every
  admission boundary. The final byte vector compares equal to the original action and has SHA-512
  `3aaa518f65a222bdf0bbdf3fd374cb45e983028844564729ab47ccd8296b1b0e2241fd9f393dd8c1ddeb45266dca18806853c82e4ecbdb5c91864013ff09ad6c`.
  The focused exact-relation suite passes 11/11, including the grammar-owned 80-case mode/mask
  matrix (26 accepted, 54 rejected), all authorization modes, stablecoin mint/burn, canonical
  round trips, and statement/context/witness/nullifier/ciphertext/balance mutation rejection.
  Retained files live under `.agent/artifacts/hx512-working-proof/`. This establishes a working
  proof and same-byte executable lifecycle, not strict PQ128, complete ZK, or production authority:
  the retained q48/s6/eta5 theorem term is still vacuous and every production flag remains false.
- [x] (2026-08-22) Implemented the source-level Plonky3 adapter boundary without manufacturing a
  Section-11 backend. It pins the only locally supported wide type, Goldilocks degree five, and
  defines canonical statement/private/state/envelope/transcript codecs plus conventional
  SHA-512/SHAKE hooks. Forty-two parser, private-input, and salt mutations pass. It records all
  105 CFW encoded oracles, the exact E320 communication floor, and every printed theorem defect;
  the actual code lengths, salt width, PCS schedule, proof bytes, theorem authority, and composed
  security remain null. The lead reran its checker under manifest SHA-512
  `1d25f9c73807d61674fbffbff7bd786227a95eaa3317117a4d76f9d6e41582f593c39305d05e766e9f5913d82bd800ba40ba56a721e6d3a4c03e3b69ee4daec8`.
- [ ] Port the full two-input/two-output transaction relation to the conventional-hash schedule.
  Evaluated in the `HX448C02` scalar host oracle: statement projection, fixed four-slot shape,
  activity/inactive padding, note/nullifier/Merkle/ciphertext/intent links, 61-bit ranges,
  multi-asset/stablecoin balance, and all five authorization transitions. Fixtures cover all 15
  nonempty masks, all-empty rejection, five modes, ordinary nonnative transfer, enabled mint/burn,
  manifest equality failures, lifecycle/freshness/dispute/cap failures, and native existential
  multi-entry behavior. Verify independently redecodes and canonically re-encodes the 869-byte
  statement, reconstructs 125 scalar limbs, rederives every frame/source map/internal chain and
  non-hash certificate, and reruns manifest-relative stablecoin validation. The M4 side statically
  lowers all 83 typed hash calls, directly binds the 18 stablecoin authority words, and now emits
  the 20+7+9 non-hash/hash-link/state-seam groups described above. This closes the former local
  width/non-hash compatibility mismatch but not the aggregate proof-relation gap: whole-manifest
  recomputation and membership, policy-identity recomputation, consensus authentication of the
  expected commitment/height, and an executed aggregate artifact remain outside the graph.
  Remaining: after disk admission, type-check and execute both scalar/M4 corpora, certify aggregate
  parity and DCE geometry, move every host-only authority into an authenticated relation or an
  exact consensus premise, select one hash profile, allocate a fresh identity, and establish
  independent semantic/compiler refinement.
- [ ] Close complete zero knowledge and composed PQ128/QROM accounting. Remaining: simulator-bound
  implementation, deployed transcript/refinement bridge, exact physical SHA-512 ledger, six
  quantitative external reductions, and independent recomputation of every probability term. The
  V6 QROM checker and its 18-test adversarial suite pass, but the checked candidate exits 2 with
  null production geometry and `composed_pq128=false` / `production_authorized=false`. A concrete active-engine
  witness-recovery event has now been found at the DECS/LVCS domain intersection; repair and
  simulator/QROM closure are in progress. The independent six-test reproduction now passes and
  recovers two complete 64-value packed witness rows with exact rank-69 algebra. The strict repair
  identity is frozen as a disjoint coset plus index-bound independent 64-byte leaf tapes, adding
  exactly 1,472 raw opened-tape bytes for 23 openings. The inactive `SMZ1` implementation now
  exact-enforces that shape, generates independent 64-byte tapes for every one of the `2^20`
  leaves, binds leaf indexes, and separates Merkle indexes from disjoint-coset algebra points;
  lightweight repair/audit suites pass 17/17, 8/8, and 6/6. A separate seven-case PIOP audit
  nevertheless found a concrete nonpacking view at points
  `[1000,1001,1002,1003,9145141821497892284]` whose linear correction factor is zero: the
  historical admissibility predicate accepts it while the verifier rejects it. The purported
  disjoint-coset binding digest also fails to derive or cross-check the engine shift or prove
  disjointness and uses a stale interpolation length. SmallWood therefore closes as negative
  evidence with `whole_proof_simulator=false`, `complete_zk=false`, `pq128=false`, and
  `production_authorized=false`; its repair is not a production workstream. Complete-ZK and QROM
  construction now belong to the Boolean-native E384/M4 candidate. The source-bound QROM package
  independently passes 41/41 dependency-free tests and binds twelve source roles under manifest
  SHA-512
  `356b719560477cc396a092538b2e3158c1a7629e574c5baff9538c2fc3fb4b65efdba1e5baa95c7a391a6a973141d2f03642a4db7b06b07e7bbdd465492c3a7e`,
  but the candidate exits 2 with 46 blockers, including opaque stablecoin authorities, no final
  hash profile, no physical transcript-call cap, no measured geometry, no complete-ZK proof, and no
  deployed reductions. Unkeyed BLAKE2b has no pinned PRF/KDF authority for the secret-derived roles;
  a keyed BLAKE2b repair lacks a bounded concrete QROM/multi-user bridge and source-bound entropy
  contract; split SHA3-512 likewise lacks a keyed-role and concrete sponge-QROM bridge. No
  conventional profile wins from generic width or core counts alone.
  The primary-source concrete-hash follow-up closes both current profiles at the security gate.
  Its independently rerun 41-test ledger records: the exact BLAKE2 multi-key result is classical,
  not quantum; the ideal-QRO secret-prefix bound is `2^-127` for 384-bit keys at `q=2^64` and
  `2^-126` for the 448-bit nullifier after the conservative epoch hybrid; the best located full-
  sponge quantum-indifferentiability bound is vacuous at that query cap for SHA3-512 and SHAKE256;
  KMAC256's applicable QIPM theorem requires an independent uniform key longer than its 1088-bit
  rate; and the HMAC QROM result assumes an ideal Merkle--Damgard compression function rather than
  HMAC-SHA3. KMAC256 is only a narrow next keyed-role experiment, not a selected suite: illustrative
  term-only arithmetic first crosses the target at a 1512-bit byte-aligned key and still lacks a
  real-Keccak bridge, public collision-role closure, or any other composition term. All 15 typed
  roles, `composed_pq128`, and production remain false. This is a reduction no-go, not an attack on
  the standardized hashes.
  The E384 successor audit has also disqualified the historical two-B128-dummy endpoint exactly:
  the mask weights `[1,Y]` have rank two, while the `Y^2` witness translation raises the augmented
  rank to three, so the two distributions are disjoint and have total-variation distance one. The
  successor therefore requires two full-E384 dummy multiplication rows, a real joint
  raw/fold/terminal observation matrix satisfying `rank(R)=rank([R|W])`, a mask generator inside
  the relation kernel, independent index-bound 64-byte tapes, and a witness-free whole-proof
  simulator. The current seam deliberately leaves `complete_zk=false` and production false.
  The lead independently reran its dependency-free field harness: 32/32 Rust tests and 8/8
  certificate tests passed, the source-bound candidate reported
  `9c26d8979ff053ad5888f99dd72e43675af9712af2832a4a314e59842848be2a`, and the checker exited 2
  with `complete_zk=false` and `production_authorized=false`, exactly as the negative gate requires.
  The provisional mixed-BaseFold PCS then failed an additional generic complete-ZK gate: its scalar
  Gao--Mateer encoding is systematic at leaf zero and the initial opening exposes raw `pi` and
  `omega` separately, so appended dummy rows and per-leaf hash tapes cannot mask an active source
  coordinate. Conditioned on querying that leaf, two valid witness views can have total-variation
  distance one; the event has probability `q/L`, far above 2^-128 for the retained depths. A
  surviving BaseFold design therefore needs a disjoint commitment domain plus an actual
  `P + Z_H R` polynomial mask with enough independent coefficients for the entire opened view, and
  must recompute degree, rate, query count, compact authentication, and proof bytes. Current PCS,
  complete-ZK, and production flags remain false.
  Syntactically unused room in an `n16` tier is not yet mask capacity: zero direct overhead is valid
  only if the backend proves those tail coordinates are outside the relation domain and may be
  randomized without invalidating the MLE/reduction or verifier-known padding. Otherwise `Z_H R`
  raises the degree and forces a larger committed tier.
  The source-bound audit now checks every admitted Gao--Mateer depth/rate pair (`d=1..20`,
  `r=1..6`) and finds `codeword[0] = message[0]` in all 120 cases. Pair sampling opens leaf zero
  with exact probability `q/L`, and all 56 exact eight-symbol/three-pair schedules leak; conditioned
  on that event the total-variation distance is one, giving at most about 25 bits of statistical
  hiding at the largest retained domain. A source-faithful repair requires Diamond's blind
  commitment, virtual oracle, `ell+1` setup, high-coefficient randomization, interleaved
  sumcheck/FRI, terminal `c0/c1`, and BCS salts. The current mixed backend implements none of that;
  its valid negative certificate exits 2 and every capability remains false. Ligerito also has no
  complete-ZK credit until a separately specified hiding wrapper and whole-view simulator pass.
- [ ] Bind one canonical proof envelope through every production hop while retaining two release
  locks. Completed as rejected parser evidence: inactive V6/Epsilon recognition under the
  profile-3/domain-2 identity,
  the exact 74-byte SWV6-v2 header, 893-byte statement, proof offset 967, `HGR6RM02`
  descriptor-manifest binding, exact-consume parser,
  inline-only source selection, typed node-context binding, whole-envelope proof-binding hash, and
  all release capabilities false; isolated
  suites pass 8/8 and 16/16. The 512-KiB limit is only a provisional parser-safety ceiling and the
  verified proof bound remains zero. Remaining: wire the identical bytes through real wallet/RPC/
  relay/durable mempool/mining/block/sync/reorg/fresh-node paths and retain mutation/restart
  artifacts; the candidate must remain absent from active version mapping and release-manifest
  authorization. Completed substeps: wallet/RPC/persistence APIs no longer truncate 48-byte
  action IDs, proof-cache reads no longer authorize consensus admission, and reorg replay always
  invokes artifact verification. The Rust/Lean cache-hit admission outcome and its vectors are
  removed: every structurally accepted tx leaf now requires backend verification. Typed
  provisional IDs can no longer be confused with canonical action IDs, and the 56-byte PQ-margin
  consensus identity package is present but deliberately inactive.
  A source-pinned transport audit confirms that the latent generic inline `Vec<u8>` carrier can
  preserve a native artifact through wallet construction, RPC `public_args`, relay encoding,
  canonical sled bytes, mining action bytes, block/range sync, reorg replay, and startup replay.
  It is not an active end-to-end path: local RPC, peer prefix admission, block import, and startup
  re-admission all invoke the fixed route gate first, and action 1 currently rejects before proof
  decoding or verification. The later consensus path also hard-decodes `NativeTxLeafArtifact` and
  bypasses the generic verifier registry. Current 48-byte wallet/action/state/storage/consensus
  fields cannot reconstruct the diagnostic 56-byte HX448 statement, and no canonical 48-to-56
  adapter exists. A fresh rules-owned action, state, storage, header/context, wallet, and verifier
  dispatch must therefore migrate atomically; padding, truncation, or reinterpreting actions 1/2
  is forbidden. Existing restart tests include `cfg(test)` bypasses and are not final lifecycle
  evidence. Remaining: traverse the actual components with the final retained proof and exact
  invocation/byte-identity assertions under a fresh selected identity, including a fresh-node
  fixture and recomputed-outer-commitment mutation cases.
  A later exact lifecycle audit narrowed the reusable seam and the atomic migration obligations.
  The generic `PendingAction.public_args` path already preserves opaque inner bytes through wallet
  SCALE/Base64 RPC, exact-consume decode, sled transaction plus flush, peer HNW1 relay, mining
  snapshots, block `action_bytes`, range/chunk sync, suffix replay, and reorg orphan recovery. It is
  not proof authority: every user route rejects first, `block_flow` hard-decodes the legacy native
  artifact, and orphan re-admission lacks an immediate cryptographic reverify before durable
  upsert. Current action/state/block/work/body/root identities also contain 32/48-byte seams and
  may not be padded, truncated, or hash-again adapted into the fresh W64 system. The selected route
  therefore needs one fresh inline action, typed W64 projector/verifier dispatch, W64 pending/
  storage/block/sync/locator/reorg identities under a fresh genesis, immediate orphan-proof
  re-verification, and one release lock. Required retained tests cover cap +/- 1, every early parser
  mutation, proof mutation with recomputed outer IDs, crash points around transaction/flush/
  publication, startup quarantine, tip-change mining, deep block mutation with recomputed PoW and
  roots, inline plus chunked empty-cache sync, and reorg/WAL restart. No checkpoint, receipt, or
  process/persisted cache may authorize validity.
  The first fresh W64 transport component is now executable but remains unallocated and inactive:
  `protocol/shielded-pool/src/hx512_inline_transport.rs` accepts exactly a 983-byte statement,
  big-endian nonzero `u32` proof length, one inline capped proof, and 2,147 ciphertext bytes for
  each active output in ascending slot order, for total
  `987 + proof_len + 2147 * active_output_count`. The caller supplies the exact `[0..186]`
  identity and proof cap; no magic, version, action, route, or production cap is allocated. An
  independent red team then retained a same-length proof-substitution counterfeit that the first
  validator API accepted because it never received proof bytes. The repaired API separates an
  allocation-free 987-byte syntax preflight from mandatory admission, requires the exact proof
  verifier over the raw statement and proof, returns a distinct admitted action type, rejects the
  retained substitution through `ProofRejected`, defers all expensive hooks until exact-length
  validation, removes infallible full-frame `Clone`, provides explicit fallible duplication,
  supports owned-frame admission without a second copy, proves the architecture-independent wire
  ceiling `4_294_962_014 = u32::MAX - 987 - 2*2147`, and separately hard-caps this inactive
  implementation at 4 MiB of proof / 4,199,585 bytes maximum action. Neither ceiling is the
  production cap; the eventual source-owned manifest must freeze a smaller measured cap and every
  outer network/RPC/block framer must enforce it before buffering. The generic hook-admitted type
  is not consensus authority; only the future compiled release verifier may provide that boundary.
  The root independently
  replayed all 13 focused tests, all 38 shielded-pool library tests, and the no-default-features
  check. The updated checkpoint is `.agent/hardening/hx512-inline-transport-20260822.json`. This
  proves a canonical parser, mandatory verifier hook, and raw byte carrier only; it does not yet
  exercise a concrete proof verifier, wallet, node, durable store, block, sync, reorg, or fresh
  node.
- [ ] Add Lean semantic/refinement gates and Rust conformance vectors without crediting finite
  vectors as universal proof-system or compiler refinement.
- [x] (2026-08-22) Verified the current release posture with dependency-free gates. The legacy
  SmallWood production checker exits 1 because `production_eligible` is false; the V5 candidate
  checker passes only as `posture=inactive`; and the same manifest exits 1 under
  `--require-authorized`. This proves the checkout is fail-closed today, not that its activation
  mechanism is sufficient. The successor still needs artifact-derived SHA-512 authority and a
  release-policy ratchet that cannot be satisfied by editing legacy claim booleans.
- [x] (2026-08-22) Landed and independently reran that source-owned release-policy ratchet without
  allocating authority. The historical checker now accepts only the exact research-only posture
  and then unconditionally refuses release; its suite passes with 26 mutations rejected. The
  successor checker has an empty immutable source registry, canonical unselected configuration,
  exact source-owned identity/evidence schema, bounded no-follow reads, recomputed SHA-512 and two
  distinct retained-proof requirements; its suite passes with 38 mutations rejected. The source
  identity separately binds consensus, transaction, all three stablecoin, full SHA-512 transcript,
  and proof-commitment widths (the live test fixture pins each stablecoin width to 48), so a mixed-
  width statement cannot hide behind one
  generic digest parameter. The historical diagnostic and the successor `--diagnostic-only`
  invocation exit 0; both release-authorizing invocations exit 1. The exact `v*` tag-push workflow now uses
  a dedicated first dependency-root job: pinned checkout, then isolated `/usr/bin/python3 -I -B`
  execution of the successor checker on the exact selection path with `--require-authorized`, then
  both regression suites. Every security/build/draft-publication job depends transitively on that
  result. The complete workflow bytes are SHA-512-pinned in both the first authorization checker and
  the policy checker; any drift rejects before a security, app, build, or publication command can
  execute. The release-policy parser additionally pins the top-level trigger, job inventory, runner and default
  execution context, checkout, command arguments/order, artifact assembly, and only write-authorized
  publication step; adversarial mutations reject alternate events, extra flow/block jobs, soft-fail,
  interpreter/environment injection, flag stripping, selection substitution, and early/unverified
  publication. Its dependency-free negative suite passes. An independent source-only rereview of
  the six-file release-gate scope found no known bypass; third-party action internals, hosted-runner
  images, live GitHub rulesets, and the semantics of any future nonempty registry remain explicitly
  outside that result. This is still only an
  empty-registry byte lock: candidate-specific certificate semantics, native verifier execution,
  binary-manifest readback, consensus-cap readback, and lifecycle replay remain required before a
  source profile can be added.
- [ ] When disk admission reaches at least 28 GiB, build and measure two independent maximum-shape
  proofs, retain their exact bytes and manifests, restart-verify them, and run the complete release
  gate. No proof-byte frontier exists until that happens.
- [ ] Update `DESIGN.md`, `METHODS.md`, the opening README whitepaper, threat model, API docs, and
  release configuration to match the verified implementation and its remaining assumptions.
  The three canonical architecture/methods/whitepaper surfaces now state that the qualifying
  frontier is empty, there is no provisional leader, every HGF6 identity is permanently rejected,
  and fresh `HX448C02` is a mixed-width diagnostic with `HX448C01` explicitly retired. They also
  record the no-winner LaZer challenger result and the framed RFC 7693 BLAKE2b-384/v2 live-policy
  compatibility boundary. Remaining: align those surfaces to the eventual fresh
  conventional identity after a backend/profile qualifies, then update threat model, API/release
  documentation, and final source-bound artifacts.

## Surprises & Discoveries

- Observation: The inherited relation and live stablecoin admission do not implement a monetary
  authorization policy. An enabled SingleKey output-only transaction can create stablecoin value
  with no input, issuer secret, collateral opening, oracle opening, or attestation opening. The
  only live issuance checks are nonzero magnitude and
  `abs(issuance_delta) <= max_mint_per_epoch`; consequently two transactions can each consume the
  entire advertised epoch cap. `min_collateral_ratio_ppm` participates in a policy hash but in no
  executable inequality. The relation also gates Merkle-root equality only by active inputs, so an
  output-only proof accepts any anchor even though native admission separately requires that
  anchor to occur in root history. These are accepted counterexamples, not missing documentation,
  and they invalidate every current "full relation" and proof-size projection as a production
  candidate. A sound repair needs a fresh grammar with issuer capability, canonical opened
  oracle/attestation semantics, bounded collateral arithmetic, an authenticated per-policy epoch
  transition, and a verifier-owned no-input anchor rule.
  Evidence: `full_blake2b448_relation::validate_stablecoin_manifest_entry`,
  `validate_authorization_activity_shape`, the active-input Merkle equality, native
  `evaluate_native_stablecoin_policy_authorization`, and the retained executable counterfeit
  corpus under `.agent/hardening/hx512-full-relation-compile/`.

- Observation: The diagnostic relation's mask and native-value language is broader than the live
  action route. It accepts 33 of 80 mask/mode pairs per stablecoin branch, whereas native payload
  admission requires at least one nullifier and at least one commitment and therefore retains only
  26 of 80: SingleKey 9, AccumulatorInit 6, ApprovalStep 2, ValueLockCreation 6, and
  FinalThresholdSpend 3. Native transfer `value_balance = 0` is also not a direct parsed equality:
  the action-side binding preimage hard-codes zero, the proof-side preimage uses the decoded value,
  and equality follows only through the legacy 32-byte BLAKE2 binding hash. A fresh route must
  directly bind a canonical zero field and must classify all 80 cells according to the 26/54 live
  split. Even under that narrower shape, a mode-0 mask-13 witness with one ordinary native input,
  native change, and a new stablecoin output remains an accepted permissionless mint.
  Evidence: `node/src/native/admission.rs` payload admission and binding-hash construction plus the
  HX512 executable mask-13 counterfeit.

- Observation: SmallWood's compact historical proofs do not survive the current occurrence-row
  Boolean adapter. The strict wire grows by roughly 60 bytes per witness row, but that executable
  packing needs at least 1,258,569 hash-only rows: 280,757 canonical rows plus 977,812 operand-
  occurrence rows. That implies at least 75,589,554 inner-proof bytes before non-hash constraints
  and exceeds the wire's `u16` matrix-column limit. The 1,344,828-byte retained M4 artifact is not
  qualifying, but SmallWood already loses its size comparator at row 21,157. Preserving the
  SmallWood LPPC/DECS engine requires a fundamentally different Boolean-native arithmetization and
  wire, not a repair to that adapter. The later direct radix-4 K=1024 screen is exactly such a fresh
  arithmetization and therefore supersedes only the blanket engine-level disqualification, not this
  adapter-level result.
  Evidence: the source-linked mixed architecture size tournament and exact
  `smallwood_engine.rs` serializer/configuration formula.

- Observation: There is no standardized `SHAKE512` in FIPS 202 or RustCrypto. A Keccak sponge with
  rate 72, capacity 1024, and SHAKE suffix `0x1f` has attractive generic bounds but is a new
  construction, so it cannot satisfy the conventional-hash/no-new-authority gate. The standard
  Keccak primitive at rate 72 is fixed-output SHA3-512 with suffix `0x06`; outputs longer than one
  digest must be expressed as separately domain-tagged standard invocations or through a reviewed
  standard KDF, not by renaming a custom sponge.
  Evidence: the Boolean-compiler KAT audit and the HGF6HR02 QROM role audit.

- Observation: Uniform SHAKE256-448 is not a defensible strict composed profile even though its
  448-bit output gives collision margin. `sp.keys2` is a secret-key expansion, `nullif.2` is a
  keyed nullifier/PRF, and the note, policy, accumulator, and value-lock roles need hiding or
  preimage resistance in addition to binding. SHAKE256's 512-bit capacity caps classical preimage
  strength at 256 and generic PQ preimage strength at exactly 128, so adding any PCS/IOP/QROM/
  history term drops the composition below 128 bits. The repair must use a standardized
  wider-capacity primitive for secret roles and SHAKE256-448 only for reviewed collision-binding
  roles. The exact mixed call/core count must be derived from executable traces; a hand total is
  not authority.
  Evidence: the role-by-role V6 QROM audit and FIPS-202 rate/capacity boundaries.

- Observation: The isolated M4 scalar oracle is not the exact live Hegemon relation. It forces
  `value_balance = 0`, requires at least one input and at least one output, and requires enabled
  stablecoin version/issuance/policy/oracle/attestation fields to be nonzero. Live witness/public
  semantics instead enforce `native_delta = fee - signed_value_balance`, admit input-only burns and
  output-only mints while rejecting only the all-empty mask, and allow canonical zero issuance,
  version, or digest values when stablecoin is enabled. These are consensus-language differences,
  not optimizations. The scalar oracle and executable R1CS must match the live semantics and cover
  positive/negative value balance, all 16 masks, zero-issuance stablecoin, mint, burn, and ordinary
  conservation before the relation can be called full.
  Evidence: `witness.rs`, `public_inputs.rs`, `smallwood_semantics.rs`, and the V6 boundary
  red-team differential review.

- Observation: Canonical authorization frames have mode-dependent byte lengths (136, 143, or
  181 bytes), so compiling `SHAKE(frame)` independently would make the committed wire shape depend
  on the private authorization mode even though every arm costs two permutations. The repair is
  two fixed two-block pipelines: each contains all five canonical arms, constructs each arm's FIPS
  padding internally, one-hot selects all 2,176 absorption bits, and binds every non-dummy source
  and 112-byte digest target. Isolated mutation tests cover selector, mux, padding, frame domain,
  length, and source coverage and pass 22/22 with the shared statement suite.
  Evidence: `smallwood_shake256_full_relation::fixed_authorization_mux_relation` and its focused
  tests.

- Observation: `HGR6RM02` hashes a deterministic schema/domain/QIR descriptor, not the serialized
  executable constraint program or compiler source. Calling its digest a compiled-relation binding
  would create false consensus authority. The SWV6 release boundary therefore still needs a
  deterministic executable-program/source binding derived after the full compiler and adapter are
  frozen; until then every capability remains false.
  Evidence: `full_shake448_statement::v6_relation_manifest`, the adapter's shape digest, and the
  V6 boundary red-team review.

- Observation: The corrected 893-byte semantic field layout is reusable, but its current codec is
  not a successor identity. `full_shake448_statement` hard-codes rejected magic `HGF6ST02`,
  proof-profile 3, domain-set 2, and descriptors that name rejected `HGF6HR02`. A new relation that
  merely wraps `FullShake448Statement` would silently reinterpret a disqualified consensus
  language. The dual-profile compiler must instead consume typed semantic fields or a fresh
  diagnostic codec that rejects every historical identity; the final statement/action/backend/
  profile/domain identity remains unallocated until one compiled hash and PCS profile wins.
  Evidence: the statement constants, codec, activation predicate, and descriptor strings in
  `full_shake448_statement.rs`.

- Observation: Historical `Sha512Level5` cannot be reused merely by absorbing the SWV6 header and
  statement. Its transcript and Merkle domains are historical, and SmallWood's binding-word API
  requires an eight-byte-aligned preimage. The fresh successor freezes `HGV6PB02`: 1,114 payload
  bytes and exactly 1,128 bytes / 141 little-endian words with no alignment padding. The
  callback-free verifier exact-parses SWV6-v2 and requires SMZ2, constructs that
  preamble internally, then currently fails with `FreshV6TranscriptBackendUnavailable` before any
  legacy verifier can run.
  Evidence: `smallwood_v6_adapter::encode_v6_binding_preamble` and
  `verify_v6_smallwood_envelope_exact`.

- Observation: The current checkout documents two mutually incompatible proof-system selections.
  `README.md` and portions of `DESIGN.md` select a standalone SHAKE256 binary proof, while the
  inherited handoff selected SmallWood with a BLAKE2b-384 relation. Exact geometry has since
  disqualified SmallWood's Boolean adapter, and exact role accounting has disqualified the uniform
  SHAKE256 semantic profile. Production remains fail-closed, so this is stale design text rather
  than dual authority; all canonical documents must be rewritten only after the Boolean-native
  winner and standard hash profile are frozen.
  Evidence: `README.md` transaction-proof sections and `DESIGN.md` transaction hash/profile
  paragraphs name the standalone path; the active SmallWood source still uses V4/Gamma and
  Poseidon relation rows.

- Observation: Historical compact SmallWood proof measurements establish a promising size prior,
  not qualification for this plan. Their relation and security profile must be re-measured after
  the SHAKE relation, complete-ZK, and strict security changes.
  Evidence: the historical pre-output-hardening result is about 87 KiB, while retained active-like
  Level-5 reports are about 113--118 KiB. None uses the qualifying relation or complete-ZK repair,
  and the current qualifying production frontier is empty.

- Observation: The disk gate is a correctness gate, not a performance inconvenience. Building a
  proof below it risks exhausting the host and would violate the bounded experiment contract.
  Evidence: `df -h .` reported about 19 GiB available on 2026-08-22.

- Observation: The current 78-field V4 statement cannot be reused for exact conventional-hash
  outputs. Six Goldilocks values cannot losslessly carry an arbitrary 384-bit digest, and the
  qualifying full relation requires a richer V6 statement with activation, network,
  ciphertext-size, five-mode, and intent context. For SHAKE256-448, each 56-byte digest can be
  projected losslessly into eight byte-aligned 56-bit Goldilocks limbs while the canonical raw
  bytes remain wire authority.
  Evidence: `TransactionVerifierInputs` uses `[Felt; 6]` digest slots and the inherited V5 envelope
  freezes 78 fields, while the historical `HGF4ST02` relation fixes an exact 853-byte semantic
  inventory that V6 migrates to 893 bytes without modular reduction.

- Observation: Migrating wallet/node action-result APIs from accidental 32-byte truncation to the
  existing typed 48-byte action ID closes an exactness bug but does not finish the strict profile.
  A 384-bit collision digest has only 128 bits of generic quantum collision work and leaves no
  positive composition margin. Fresh V6 consensus/action/root authorities therefore need
  lossless typed outputs from the selected standard 448-bit registry under a fresh genesis/rules
  hash; historical 32/48-byte identities remain decode-only. The current 869-byte `HX448C02`
  mixed-width diagnostic preserves the three live 48-byte stablecoin authorities, but still is not
  that migration contract because manifest-state equality and every fresh consensus identity remain
  absent.
  Evidence: the completed wallet/RPC/persistence migration and the active V6 consensus-binding
  audit.

- Observation: The production release gate began as a legacy caller-document check that could be
  satisfied by flipping five claim-ledger values, while the adjacent V5 checker was invoked without
  `--require-authorized`. The historical V4/Gamma checker is now permanently diagnostic: it
  requires every legacy authority flag false and can never authorize a successor. A separate
  identity-neutral successor gate has an empty source-owned registry, an exact canonical unselected
  document, bounded no-follow reads, full network/chain/genesis/rules/program/verifier/transcript/
  hash-role identity fields, and a SHA-512-pinned exact evidence bundle requiring two distinct
  proof artifacts. Its 38 adversarial fixtures pass, including release-workflow binding,
  stablecoin-width, and truncated-
  transcript identities; `--diagnostic-only` succeeds, and authorization
  mode fails because the registry is empty. This is an exact-byte release lock, not semantic
  certificate execution: it does not yet recompute the security/ZK/refinement certificates, invoke
  the shipped native verifier, or replay lifecycle artifacts. The exact `v*` tag-push workflow now
  makes an isolated `transaction-proof-authorization` job the dependency root, runs the successor
  checker first with `/usr/bin/python3 -I -B` and exact `--require-authorized` arguments, then runs
  both regressions. The empty registry therefore closes every tag release. The static policy suite
  first verifies the whole-workflow SHA-512 pin, then pins the trigger, exact job grammar/inventory,
  checkout, runners/contexts, command order, artifact
  assembly, and draft publication; it rejects alternate/scheduled triggers, extra block or flow-map
  publication jobs, deletion/soft-fail, interpreter or environment injection, removed authorization,
  and selection substitution. After a winner exists, candidate-
  specific executable validators and release-binary/consensus readback must precede the immutable
  source-registry entry; workflow presence alone cannot authorize cryptographic semantics.
  Evidence: `scripts/check_smallwood_production_authorization.py`,
  `scripts/check_transaction_proof_successor_authorization.py`, their test suites,
  `config/transaction-proof-successor-selection.json`, `scripts/check_smallwood_v5_candidate_gate.py`,
  and the `transaction-proof-authorization` job in `.github/workflows/release.yml`.

- Observation: One exported wallet compatibility path constructs the wrong artifact layer.
  `ShieldedTxBuilder` stores raw `TransactionProof.stark_proof` bytes in a bundle documented and
  consumed as a complete `NativeTxLeafArtifact`; no production callsite was found, but an external
  caller would reach the node's hard native-artifact decoder and fail. The successor wallet API
  must expose only the final self-contained artifact builder, with raw-inner-proof construction
  private, test-only, or explicitly historical.
  Evidence: `wallet/src/prover.rs`, `wallet/src/shielded_tx.rs`, `wallet/src/rpc.rs`, and
  `node/src/native/admission.rs`.

- Observation: A 384-bit collision-binding hash cannot meet the composed target after another
  positive failure term is added. Generic quantum collision search gives exponent `384 / 3 = 128`;
  any QROM, PCS, IOP, grinding, or union contribution makes the summed failure probability exceed
  `2^-128`. The relation gadget is generic over RFC 7693 output length, so a wider output can reuse
  the same compression trace while paying only additional output-binding/public-statement cost.
  Evidence: `circuits/transaction/src/smallwood_v5_envelope.rs::authorize_capabilities` rejects
  relation hash widths below 400 bits, and `smallwood_blake2b384.rs::blake2b_relation` supports
  every RFC output width from 1 through 64 bytes.

- Observation: Widening SHAKE256 output to 448 bits raises generic quantum collision work to about
  149 bits, but it does not raise SHAKE256's generic preimage-strength ceiling above 256 classical
  bits, or 128 bits under Grover, before composition. The V6 certificate must therefore classify
  every semantic and transcript role and prove that only collision/random-oracle properties with
  positive margin are required. If any unavoidable preimage/unpredictability term is capped at
  128, SHAKE256 output widening is not a repair; that role must move under a fresh profile to a
  standardized wider-capacity conventional construction such as SHA3-512, SHA-512, or
  BLAKE2b-448. No current source or
  certificate discharges this role-by-role gate.
  Evidence: the architecture red-team and the still-missing
  `shake256_448_semantic_binding` quantitative reduction in the V6 QROM checker.

- Observation: Boolean BLAKE2b is also structurally the wrong relation hash for compact SmallWood.
  Its inherited 77-call/164-compression partial schedule accounts for exactly 16,322,454 scalar
  constraints and 255,100 per-call packed-64 core rows, plus 1,906 source-input and 462 output-binding
  rows, before transaction logic. The retained M4 slice uses 83 Keccak-f
  permutations and measures 51,449 characteristic-two AND constraints, but that number is not a
  Goldilocks/SmallWood row count. The earlier 90-permutation SHAKE projection had 54,000
  lane-word ANDs and 164,160 round XOR-family operations, but it too omitted ciphertext hashing.
  The disqualified uniform fixed-shape source has 79 invocations and 124 Keccak-f permutations.
  The rejected HGF6HR02 schedule has the same 79 calls but 145 permutations because its
  nonstandard rate-72 XOF absorbs more blocks and 112-byte outputs require an extra squeeze. Exact
  rows for a conventional replacement remain unmeasured, so the prior 1.15x--1.97x comparison is
  no longer a qualifying frontier result.
  Evidence: the completed `smallwood_blake2b384` worker's isolated gate report and the retained
  full-relation SHAKE manifest/source counter.

- Observation: The retained 83-permutation M4 geometry is not the exact full proof relation. It
  externalizes the public `intent.1` hash (six Keccak-f calls), `bal.tag1` hash (one call), and both
  full ciphertext hashes. Each fixed 2,147-byte ciphertext produces a 2,182-byte `ct.hash1` frame
  and costs 17 Keccak-f permutations. Those additions produce 79 invocations/124 permutations in
  the disqualified uniform SHAKE256 relation. HGF6HR02's 79/145 projection is also nonqualifying
  because its wide XOF is nonstandard. Any 83-, 90-, 124-, or 145-core projection is evidence only
  until the final conventional registry is compiled, even if its host checks are deterministic.
  Evidence: `M4_FIXED_KECCAK_PERMUTATIONS`, `FullM4Wires::derived_intent`, and the full-relation
  realization map.

- Observation: A distinct same-source M4 successor now statically expresses the intended 83-call
  `HX448C02` hash inventory, including intent, balance, and both ciphertext hashes. Mixed BLAKE has
  28 RFC 7693 compression cores plus 105 SHAKE permutations; split SHA3 has 46 SHA3 permutations
  plus the same 105 SHAKE permutations. Its pre-DCE hash-only ledgers are respectively
  79,128 AND / 265,963 linear / 452 BMUL and 90,600 AND / 327,437 linear / 444 BMUL. The exact
  typed lowering audit closes every call index once, the local 688-file Binius tree pin recomputes,
  and source-only format/checker gates pass. None of those facts is compiled relation geometry,
  aggregate cross-call constraint evidence, executed scalar parity, complete ZK, a QROM
  certificate, or measured proof bytes. The 869-byte scalar/M4 grammar now preserves policy,
  oracle, and attestation as three direct 48-byte values and mirrors lifecycle admission relative
  to a whole supplied manifest/height. The later source checkpoint adds M4 lifecycle,
  manifest-state equality, and current-height equality constraints, but that is still compatibility,
  not authority: whole-manifest recomputation/membership and consensus authentication remain
  host-only, the kernel root excludes policy entries, and the three opaque 384-bit authorities
  union to at most about 126.415 generic quantum-collision bits before any proof-system loss. This
  checkpoint therefore has no leader or production authority.
  Evidence: `m4-full-blake448-e384-candidate/src/mixed_candidate.rs`, its dependency-free
  `check_source.py`, and the ignored 66-case scalar/M4 differential corpus.

- Observation: The mixed B128/E384 M4 competitor has no qualifying sub-512-KiB artifact. Its
  488,460-byte one-copy figure is a serializer projection from the retained weak-profile topology;
  the E384 coefficient-lane PCS is unimplemented, complete ZK and composed QROM are false, and its
  83-permutation proof core externalizes hashes required by the V6 relation contract. It therefore
  remains tournament evidence rather than an architecture winner. If it later ships a smaller
  qualifying artifact under the same gates, this plan must concede the tournament.
  Evidence: `.agent/PQC_ZK_PRODUCTION_EXECPLAN.md` and the retained 1,344,828-byte M4 artifact.

- Observation: The first executable E384 BaseFold PCS checkpoint is not yet the M4 opening layer.
  It contains a scalar Gao--Mateer B128 encoder, E384 folds, SHA-512 Merkle commitments, exact
  coefficient-lane parsing, and compact-frontier data types, but the in-progress serializer and
  verifier still reference the superseded per-query opening grammar. Query sampling is still with
  replacement, the prover derives every leaf tape from one seed rather than consuming independent
  per-leaf randomness, and all groups must have one equal dimension. The retained M4 proof has
  mixed input-oracle depths 13/18/20/11 and FRI depths 16/12/9, so this checkpoint cannot bind its
  actual proof view or yield a proof-byte claim. Qualification requires a canonical
  without-replacement schedule, end-to-end compact multiproofs, independent tapes, and either a
  real mixed-depth transcript/PCS or an exact common-padding compiler with measured cost.
  Evidence: the in-progress `strict-mixed-field/src/mixed_basefold_pcs.rs` and retained
  `m4-strict-full-shake400-v1/BYTE_PROFILE.md`.

- Observation: The current strict-security package is an evidence registry and exact-arithmetic
  calculator, not a cryptographic certificate. Its lightweight suite passes 14/14 adversarial
  cases, while the checked-in candidate exits 2 with 0/24 receipts verified, every production
  geometry field unmeasured, and `complete_zk`, `pq128`, and `production_authorized` all false.
  Synthetic receipt fixtures demonstrate parser behavior, not the semantics of a reviewed proof.
  Evidence: `.agent/hardening/smallwood-pqc-zk/strict_profile.py`, its test suite, candidate
  certificate, and empty trust root.

- Observation: VEIL (ePrint 2026/683) is the first theorem-backed generic route found for wrapping
  a hash-based multilinear IOP without proving its hash calls inside another circuit, but it is not
  a free zero-knowledge flag for Ligerito. The compiler masks non-oracle transcript values and
  routes oracle reads through a separately zero-knowledge PCS. The public `slop-veil` proof of
  concept is explicitly experimental/unaudited and depends on BaseFold; it does not supply an
  E384 characteristic-two Ligerito PCS, Hegemon observation map, QROM Fiat--Shamir composition, or
  retained proof. A viable screen must instantiate the exact VEIL MIOP interface, zk-code/random-
  column assumptions, algebraic constraint wrapper, and hiding PCS on the selected backend and
  price all of them. The published proof-of-concept overhead percentage is non-transferable.
  Evidence: `https://eprint.iacr.org/2026/683`, the authors' VEIL formalization, and the published
  `slop-veil` crate dependency/API surface.

- Observation: The current one-level Ligerito transcript fails complete ZK before VEIL can be
  applied. At one fully active `E384/B128` residual coordinate, the retained mask image has rank
  one while same-relation witness differences span rank three; a left-null functional therefore
  distinguishes valid witness views with conditional total variation one. Three independent B128
  coordinate masks close that one local block only. The source-pinned audit passes 9/9 negative
  tests and reports `current_mask_rank=1`, `current_joined_rank=3`, all authority flags false. The
  published `slop-veil` trait facade cannot substitute Hegemon's PCS: its only concrete context is
  two-adic KoalaBear/BaseFold, while `GF(2^128)` has no positive power-of-two multiplicative
  subgroup. A qualifying path must export the interactive M4 MIOP, build a new additive binary
  zk-Ligerito MCS, arithmetize the whole verifier predicate, and compose its simulator with
  Fiat--Shamir/QROM. The direct source-structure floor `96q + 192` bytes omits that dominant work
  and is not a proof-size estimate.
  Evidence: `.agent/hardening/ligerito-e384-veil-complete-zk/`, VEIL ePrint 2026/683, and the pinned
  `slop-veil 6.4.0` source archive.

- Observation: The bounded primary-source challenger tournament also returns `winner=null`. LaZer
  Pack is the only nominally smaller challenger at its roughly 110 KB paper headline, but the paper
  statement is not Hegemon's exact relation and no retained artifact was produced. Its Pack theorem
  instantiation gives `5 * 2^-128` (about 125.68 bits), while the located Appendix C argument is a
  classical-ROM heuristic and the pinned implementation fixes a 128-bit challenge. Even a favorable
  finite-QROM measure-and-reprogram accounting with `q_H = 2^64` requires `lambda >= 261` and
  `log2|C| >= 260`, before the absent quantum interactive-PoK reduction. Widening that implementation
  is an unreviewed protocol redesign with unknown proof bytes. Labrador, WHIR/VEIL, BaseFold,
  Ligerito, and the remaining surveyed lanes also fail at least one exact-relation, complete-ZK,
  finite-QROM, self-contained-artifact, or measured-byte gate. No architecture is selected.
  Evidence: `.agent/hardening/pq-architecture-challenger-screen/REPORT.md` and `ledger.json`.

- Observation: CFW26's printed Section 11 R1CS reduction is not presently a production authority.
  Construction 11.4 has an algebraic coefficient conflict between Steps 3/8 and its decomposition/
  value-claim proof, and Step 9 is ill-typed against Definitions 5.2 and 5.4. No public erratum was
  located, and the merged Plonky3 Hiding-WHIR PCS intentionally omits this reduction. A locally
  chosen repair could be tested as a new construction, but it cannot inherit the paper's theorem
  without a checked proof and refinement.
  Evidence: CFW26 Construction 11.4, Definitions 5.2/5.4, its page-71 HVZK proof, and Plonky3 issue
  1590.

- Observation: A coherent local repair does not rescue CFW26 theorem inheritance. Besides the
  coefficient and typing defects, the printed endpoint selector reads the coefficient of `X`
  instead of evaluating at one, its first RBR error coordinate omits dimension dependence, and
  the encoding definition's fixed-set simulator does not justify adaptive oracle answers. The
  retained repair is consequently a new conditional nonadaptive construction, not a qualifying
  complete-ZK proof system.
  Evidence: `.agent/hardening/cfw26-parametric-repair-proof/`.

- Observation: Current SmallWood is not complete zero knowledge. Its radix-2 DECS evaluation
  subgroup contains field point 64, which is also a non-random committed LVCS coordinate after the
  active row rotation. If leaf index 163,840 is among 23 samples (probability `23 / 2^20`, about
  `2^-15.48`), the serialized subset values plus five opened evaluations form a full-rank
  Vandermonde system that recovers all 69 coefficients and hence 64 packed witness values for at
  least two rows. This is an implementation-level witness-recovery event, not merely a missing
  simulator theorem. A disjoint-coset domain can remove this exact intersection, but complete ZK
  additionally requires the paper's per-leaf random tapes/index binding and a joint proof-view
  simulator; repair cost and proof bytes are not yet known.
  Evidence: active LVCS/DECS rotation and subgroup geometry in `smallwood_engine.rs`; the
  independent executable audit under `.agent/hardening/smallwood-pqc-zk/independent-leak-audit`
  recovers both rows 41 and 416 with rank 69, while its four-opening negative control has rank 68.

- Observation: A disjoint coset is necessary but not itself a complete-ZK proof or even a complete
  implementation repair. The prover currently uses sampled leaf numbers as both Merkle table
  indexes and algebraic evaluation points. A coset profile must split those roles: indexes select
  authenticated leaves, while `shift * root^index` drives LVCS/DECS algebra on both prover and
  verifier. The new profile must also bind the paper-required opened-leaf random tape and index and
  establish a joint simulator for the entire proof view.
  Evidence: `lvcs_open`, `decs_open`, `decs_field_evaluation_points`, and the independent leak audit.

- Observation: The retained `HGS6BC02` disjoint-coset descriptor is not an executable geometry
  binding. Its digest helper checks only domain size, an interpolation-count range, and a nonzero
  shift; it neither derives/cross-checks `radix2_disjoint_coset_shift` nor tests that the coset is
  disjoint. Its positive fixture also uses the stale `(2^20, 375, 376)` geometry while the engine
  interpolation length is `nb_lvcs_cols + q` and grows with the compiled relation. It can therefore
  bless an overlapping coset and cannot support complete-ZK or source authorization.
  Evidence: `smallwood_v6_transcript::disjoint_coset_binding_digest` and the engine DECS geometry.

- Observation: Exact QROM composition cannot be instantiated from a logical transcript-call count
  alone. The SHA-512 field-XOF rejection loop is not physically capped and the optimized Merkle
  leaf path bypasses the existing digest-call profiler. Until the verifier enforces a physical
  per-proof call cap and records every executed SHA-512 invocation, the source-bound QROM checker
  must keep production authorization false.
  Evidence: the V6 QROM source audit and `.agent/hardening/smallwood-v6-qrom-composition`.

- Observation: The corrected V6 QROM ledger is executable but intentionally has no numeric
  security verdict yet. It rejects the 77/90 ciphertext-externalized geometry and the historical
  radix-2/32-byte-tape identities, then exits 2 because eight measured geometry values, a physical
  SHA-512 cap, six quantitative reductions, source pins, a consensus-enforced proof epoch, and the
  listed compiler/verifier/ZK refinements are absent. Passing 18 parser/arithmetic mutation tests
  establishes fail-closed accounting behavior, not composed PQ128.
  Evidence: `.agent/hardening/smallwood-v6-qrom-composition/composition.py` and its checked-in
  profile/test suite.

- Observation: The concrete-hash follow-up found no production-selectable conventional suite for
  all 15 security-bearing roles. Keyed BLAKE2b has an exact classical weakly-ideal-cipher theorem
  but no located real-BLAKE2 quantum/multi-user qPRF bridge. At `q=2^64`, the ideal-QRO prefix
  theorem gives only `2^-127` for a 384-bit key and the conservative 448-bit nullifier epoch union
  gives `2^-126`. The located full-sponge quantum-indifferentiability bound is already vacuous for
  SHA3-512/SHAKE256; KMAC256 requires uniform keys longer than 1088 bits and remains QIPM/single-
  user; HMAC's QROM theorem assumes a Merkle--Damgard compression QRO and does not instantiate
  HMAC-SHA3. Missing/asymptotic terms are not zero, so raw width cannot authorize the profile.
  Evidence: `.agent/hardening/smallwood-v6-qrom-composition/CONCRETE_HASH_QROM_AUDIT.md`, SHA-512
  `cf8a5f06ad2f7958e504c66d920c2b44cb026348ee52ed79f563d18fcdeb16e6d9e6be3460a9c495d0b156c432ccd7802c885eb470ed4eeacce9f4a7316f0481`.

- Observation: A distinct wire magic is not sufficient backend separation. An interim engine
  parser recognized SMZ2, but the generic DECS guard compared only strict-leaf-hiding and digest
  width, allowing the same-shaped payload to be routed through historical `Sha512Level5`; the
  public fresh selector also had an uncalled availability guard followed by a panic arm. The
  repair must enforce exact wire/backend/domain triples at every prove, parse, trace, and verify
  entrypoint, return typed errors before hashing, and mutation-test SMZ1/SMZ2 cross-routing.
  Evidence: the V6 boundary red-team review of `smallwood_engine.rs` and the pending SMZ2 patch.

## Decision Log

- Decision: Reject the inherited stablecoin/full-transaction grammar and freeze production
  authorization false; do not optimize or assign a proof identity until a fresh consensus-owned
  monetary state transition is specified and counterexample-tested.
  Rationale: policy membership, freshness, and opaque commitments cannot authorize issuance.
  The existing language permits permissionless output-only minting, cap replay, and dead
  collateral-ratio configuration. Locally strengthening only the proof predicate would also drift
  from wallet, mempool, block, sync, and reorg semantics. The smallest defensible successor must
  bind an authenticated parent policy/state root, issuer capability, canonical oracle and
  attestation openings, post-transition collateralization, cumulative epoch mint state, and an
  atomic next-state root through every lifecycle stage before its hash schedule or proof bytes are
  eligible for the tournament.
  Date/Author: 2026-08-22 / Codex.

- Decision: Re-enter the reusable SmallWood LPPC/DECS engine provisionally through a fresh direct
  radix-4, K=1024 arithmetization; keep the occurrence-row adapter, SMZ2 identity, and every prior
  V5/V6/V7 candidate identity rejected, and keep the tournament winner null.
  Rationale: the source checker conditionally reduces the HX512 hash core from at least
  1,258,569 adapter rows to roughly eleven thousand direct rows. After accounting for control
  initialization and a conservative mode-gated auth-digest link, the current conditional screen is
  11,209 base rows / 1,373,074 bytes. The dense topological indexer remains unimplemented, so the optimizer
  and exact byte total must be rerun after every control dependency and source binding is present.
  That is
  close enough to the nonqualifying 1,344,828-byte M4 comparator to justify implementation, but it
  omits the non-hash relation and has no proof, parser, simulator, QROM ledger, or verifier
  refinement. A fresh identity and measured qualifying artifact are mandatory.
  Date/Author: 2026-08-22 / Codex.

- Decision: Disqualify printed CFW26 Section 11 and any theorem-inheriting implementation from
  the production tournament; retain the repaired `c=1` relation only as an independently named
  research candidate whose full RBR, adaptive complete-ZK, and QROM proofs must be supplied from
  first principles.
  Rationale: the retained counterexamples invalidate literal perfect completeness, the printed
  first RBR error coordinate, and the fixed-set-to-adaptive simulation step. Local algebraic
  repairs close honest completeness but cannot confer the paper's theorem or production
  authority. `winner=null` remains mandatory while Ligero and other complete-ZK alternatives are
  screened and the exact all-W64 relation is compiled.
  Date/Author: 2026-08-22 / Codex.

- Decision: Keep the tournament winner null and make odd-characteristic CFW26 HVZK-WHIR the next
  theorem-backed implementation screen; do not attempt to bless the retained B128 M4/BaseFold
  opening.
  Rationale: the retained opening reveals a separable raw message coordinate and has a TV-one
  same-statement counterexample. CFW26 supplies the only retained composable whole-view HVZK plus
  round-by-round soundness topology, and CMS modified BCS can conditionally carry its soundness and
  statistical HVZK into the QROM. The paper's complete-ZK R1CS clause excludes characteristic two,
  while Plonky3 omits the R1CS layer, canonical proof grammar, strict hash profile, and exact
  Hegemon relation. The screen must therefore implement and refine a new odd-field Boolean/R1CS
  compiler and measure the full proof before it can become a winner.
  Date/Author: 2026-08-22 / Codex.

- Decision: Retain the BLAKE2b-versus-SHA3 compiled/DCE comparison only as geometry evidence; do
  not select either current semantic suite or allocate its identity.
  Rationale: the pinned Binius Shift gate is linear and spends no AND. Mixed BLAKE therefore has
  79,128 raw hash-core AND constraints versus 90,600 for split SHA3, plus 10,752 separately counted
  BLAKE rotation-linear constraints. Addition-linear, XOR, mux, counter/final, Keccak-linear, DCE,
  and oracle-shape terms are still missing from that screen. More decisively, neither suite has an
  applicable concrete-hash/QROM composition for all 15 typed roles. Identical executable compiles
  may still price reusable relation work after disk admission, but they cannot decide a production
  winner until the hash-role security suite itself is replaced and recompiled.
  Date/Author: 2026-08-23 / Codex.

- Decision (superseded at the compiled-cost gate above): provisionally select unkeyed RFC 7693
  BLAKE2b-448 for hidden/preimage semantic roles and retain
  FIPS 202 SHAKE256-448 for collision-only roles, subject to an explicit concrete-BLAKE2b-as-QRO
  instantiation assumption. Do not use keyed BLAKE2b, HMAC, or HKDF in this relation, and do not
  call the hidden-seed construction an unqualified standard-model PRF.
  Rationale: the exact maximum schedule is 15 BLAKE calls/28 compressions plus 68 SHAKE calls/105
  permutations. Prefix-free, separately tagged unkeyed calls preserve the 384-bit hidden-source
  screen without the public-key entropy and extra key-block defects. At `Q=2^64`, conservative
  hidden-point, preimage, and collision screens are about 250.093, 314.093, and 254 bits of failure
  exponent; constant-success generic work factors are about 188.547, 220.547, and 148.333 bits.
  These are primitive screens, not composed proof authorization.
  Date/Author: 2026-08-23 / Codex.

- Decision (superseded by the source-faithful ZK geometry screen): Implement a single mixed-field
  E384/B128-lane M4/BaseFold candidate before every other surviving proof architecture, without
  calling it a tournament winner.
  Rationale: it reuses the only executable Boolean M4 relation and field-extension seam, while
  avoiding the unproved repeated-B128 composition. The current E384 crate is only a toy full-table
  commitment/sumcheck, so qualification still requires a real authenticated mixed PCS, exact
  full-relation port, complete-ZK transform, SHA-512 transcript, composed QROM ledger, canonical
  parser, and measured retained artifact. The first Gao--Mateer/systematic opening failed complete
  ZK at leaf zero, so BaseFold can survive only with a disjoint commitment domain and a full
  polynomial-mask/rank repair whose new geometry fits. Ligerito remains the fallback opening layer
  if that repair is not simulatable or misses the size gate.
  Date/Author: 2026-08-23 / Codex.

- Decision: Continue one-level authenticated Ligerito/TensorSwitch with E384 algebra and SHA-512
  only as a source-faithful replacement-MIOP falsification screen; disqualify the current
  serialized transcript and masks.
  Rationale: source-faithful BaseFold complete ZK doubles the relation dimension and its pre-ZK
  q310 serializer already exceeds the retained weak M4 comparator. The Ligerito n16 model is much
  smaller, but is still a Pay1x2/non-ZK projection with no exact maximum M4 binding, hiding wrapper,
  simulator, composed QROM theorem, or retained proof, and its existing mask view has a rank-one
  versus rank-three TV-one counterexample. It qualifies only if a new interactive MIOP plus
  additive zk-MCS closes those gates and the measured full-relation artifact wins the tournament.
  Date/Author: 2026-08-23 / Codex.

- Decision: Disqualify the current SmallWood Boolean adapter from the smallest-proof lane and
  reopen the proof-engine tournament around Boolean-native architectures.
  Rationale: its hash-only static lower bound is about 75.6 MB and its exact wire shape is
  unencodable, before the full transaction relation or complete-ZK repair is charged. Historical
  87--118 KiB proofs cover an algebraic Poseidon-era relation and cannot rebut this source-linked
  full-Boolean geometry. Binius/M4 remains nonqualifying until strict PCS, complete ZK, exact live
  semantics, and production binding land, but it is the current size comparator to beat.
  Date/Author: 2026-08-23 / Codex.

- Decision: Keep the architecture tournament open after disqualifying uniform SHAKE256, the
  nonstandard mixed-SHAKE512 descriptor, and the current SmallWood Boolean adapter. SmallWood is
  retained only as negative proof-engine evidence unless a fundamentally different arithmetization
  and wire independently re-enter the tournament; no adapter repair is on the production path.
  Rationale: source-linked Boolean geometry is at least 75.6 MB and unencodable, and the complete-ZK
  audit has a concrete accepted-prover/rejected-verifier view. The next implementation must be a
  Boolean-native engine and still satisfy every gate in this plan.
  Date/Author: 2026-08-23 / Codex.

- Decision: Require exact Boolean constraints for a fresh, conventional wide-capacity primitive on
  every preimage/PRF/KDF/hiding role, while allowing SHAKE256 only for reviewed collision-binding
  roles. A host-computed digest is never proof authority. No rate/capacity/suffix combination may
  be given a standard name it does not have; the final choice must have independent standard KATs
  and explicit QROM reductions. The proof transcript remains conventional full SHA-512.
  Rationale: HGF6HR02 demonstrated that sound parameter arithmetic cannot substitute for primitive
  authority. Exact consensus execution must bind every standard invocation and application-domain
  frame without introducing a new hash assumption.
  Date/Author: 2026-08-22 / Codex.

- Decision: Require two independent authorization locks for the new profile.
  Rationale: Recognizing and parsing candidate bytes is necessary for integration testing, but an
  incomplete profile must remain unreachable both from active version dispatch and from the
  release manifest.
  Date/Author: 2026-08-22 / Codex.

- Decision: Reject, rather than allocate, the provisional V6/Epsilon profile-3 identity
  (`HGF6ST02`, `HGR6RM02`, SWV6 version 2, `HGV6PB02`, and `SMZ2`). Allocate a new identity only
  after the standardized semantic primitive and Boolean-native backend are fixed; no old parser,
  descriptor, proof, receipt, or wire may be reinterpreted.
  Rationale: the provisional identity names a nonstandard rate-72/suffix-0x1f sponge and the
  disqualified SmallWood wire. Fresh naming is still required, but assigning it before freezing the
  executable relation would create another historical ambiguity.
  Date/Author: 2026-08-23 / Codex.

- Decision: Retain the raw, independently visible chain, genesis, and rules identity fields as a
  rejected statement-design invariant, but do not authorize their provisional SHAKE256-448
  encoding or 893-byte profile. The final wire widths and digest primitive must be derived from the
  selected standard profile under a fresh identity.
  Rationale: exact three-way binding is required and must remain independently mutation-testable,
  but uniform SHAKE256 lacks positive preimage/PRF composition margin and cannot name the final
  consensus surface.
  Date/Author: 2026-08-23 / Codex.

- Decision (superseded): Preserve the exact 893-byte V6 statement as canonical wire authority and
  project the complete byte string to 128 consecutive little-endian seven-byte Goldilocks limbs,
  with three constrained trailing zero bytes, for exactly 128 public fields. This remains useful
  diagnostic codec/projection evidence only. It cannot become production authority because its
  hash schedule/identity was rejected and the active wallet, action, state, storage, header, and
  consensus surfaces are not an independently reconstructible 56-byte system.
  Rationale: The projection is injective, but injective encoding does not establish semantic
  refinement or lifecycle integration. The selected standard relation must first fix its digest
  width and executable program, then allocate a fresh statement/action/rules identity and migrate
  every authoritative producer and verifier atomically. No 48-to-56 padding, truncation, or
  reinterpretation is permitted.
  Date/Author: 2026-08-22 / Codex.

- Decision: Treat current same-byte transport as reusable latent plumbing, not production
  integration, and require a fresh width-consistent protocol family for the eventual winner.
  Rationale: The live route rejects before proof decoding; downstream code hard-decodes the legacy
  native artifact; consensus bypasses the generic verifier registry; and current authoritative
  fields are 48 bytes while HX448 diagnostics are 56 bytes. A parser swap cannot make the node
  independently reconstruct or validate the new public statement.
  Date/Author: 2026-08-23 / Codex.

- Decision: Withhold heavy builds and proof generation below 28 GiB free space.
  Rationale: The user's sealed experiment contract and retained evidence require 28 GiB admission
  and a 20 GiB hard abort; the current host has about 16 GiB free.
  Date/Author: 2026-08-22 / Codex.

## Outcomes & Retrospective

The plan is active. A real retained HX512 SmallWood proof and executable same-byte native lifecycle
now work end to end, with measured proof/action bytes and mutation rejection. No profile is
production-authorized and the retained proof is not strict-PQ128 or complete-ZK. The integration
contract therefore keeps the public route fail-closed while preserving a directly runnable proving,
verification, wallet/RPC, durable-restart, mining, block, sync/reorg, and fresh-node implementation.

## Context and Orientation

`circuits/transaction` owns the SmallWood prover, verifier, public statement, and relation. The
existing V4/Gamma path proves a 78-field statement using a compact LPPC relation and DECS opening
scheme; its transcript is conventional SHA-512, while transaction note, nullifier, Merkle,
balance, and related relation rows still depend on Poseidon2. The isolated
`circuits/standalone-full-shake256-relation-prototype` owns the exact five-mode scalar relation and
Keccak schedule that must be lowered into SmallWood; host recomputation is not a substitute for
in-proof constraints.

`protocol/kernel` owns version/profile identities and release-manifest authorization.
`circuits/transaction/src/proof.rs` owns the outer transaction-proof wrapper. `consensus` and
`node/src/native` own action admission, durable pending-action storage, relay, mining preflight,
block verification, synchronization, fork replay, and restart recovery. A proof cache may avoid
recomputation only after the same canonical artifact and public view have already verified; it
must never become validity authority.

`formal/lean` is the production-facing semantic and conformance layer. `formal/crypto` is an
isolated research package that may state cryptographic reductions but cannot be imported by
production Lean or Rust. Passing an axiom audit or generated-vector suite proves neither an
adequate specification nor arbitrary accepted-Rust-execution refinement. Every claim must label
whether it is an implementation measurement, finite conformance result, theorem, model,
certificate, or external cryptographic assumption.

The exact transaction relation has two input slots and two output slots. All sixteen activity masks
must be tested: accepted masks must enforce active note openings and inactive-zero padding;
rejected masks must fail deterministically. The relation includes canonical parsing, action family
and action id, network/chain/genesis/rules binding, version/profile/domain binding, ordered
ciphertext hashes, note commitments, input Merkle membership, nullifiers and authorization,
61-bit monetary range checks, multi-asset balance, stablecoin mint/burn policy, fee, and the five
authorization modes already represented by production semantics. Public fields cannot be free or
host-asserted.

Complete zero knowledge means that the distribution of the entire proof, including committed
oracles, claims, openings, indices, nonces, padding, and retry behavior, is simulatable from the
public statement. Random satisfiable padding or witness obfuscation is insufficient. The concrete
security certificate must compose PCS binding/proximity error, LPPC/IOP knowledge error,
Fiat--Shamir/QROM loss for every oracle and adaptive proof, deployed SHA-512/SHAKE
collision/preimage terms, grinding/retry loss, and every union or multi-proof term.
The exact integer sum must be strictly below 2^-128; rounded decimal summaries are diagnostic only.

## Plan of Work

First, freeze the architecture tournament. Inventory every implementation candidate and retain only
those with a real maximum-shape relation, complete proof privacy, a strict composed security path,
canonical self-contained bytes, and production integration. Record the exact source and artifact
for every measured result. Disqualify partial, weak-profile, sidecar, aggregate, and projected-only
results before comparing bytes.

Second, retain the completed BLAKE2b and SHAKE gadgets plus the disqualified SmallWood geometry as
tournament evidence, select a conventional primitive registry, and lower the exact relation into
the smallest Boolean-native proof engine that can satisfy strict PQ128 and complete ZK. The
compiler must constrain every absorbed byte, domain/padding bit, primitive transition, and output.
Mutating any state, frame, input, padding, schedule, or digest bit must make constraint verification
fail.

Third, define one canonical hash schedule for every relation domain and port the complete production
relation to it. Generate the statement and witness from existing semantic objects instead of
maintaining a second transaction model. Cross-check scalar host semantics against constrained
execution for all sixteen masks, every authorization mode, stablecoin mint/burn/ordinary transfer,
and mutation cases for every public binding.

Fourth, make zero knowledge and security executable. Implement the mask/simulator construction,
pin transcript sampling and retry behavior, produce exact integer security accounting, and bind the
certificate to the actual profile bytes and verifier constants. Independent code must recompute
the certificate and reject a one-bit profile or term mutation.

Fifth, add the canonical envelope and production route behind both authorization locks. The exact
same byte vector must be observable at wallet construction, RPC decode, relay decode, durable
mempool recovery, mining preflight, serialized block storage, peer sync, winning and losing fork
replay, and fresh-node import. Every parser exact-consumes and canonical-reencodes. Proof, statement,
profile, action, network, version, domain, ciphertext, balance, nullifier, Merkle, intent, truncation,
and trailing-byte mutations must reject before state mutation.

Sixth, mechanize the semantic/refinement boundary and wire it into CI/release checks. Lean should
state an independent semantic relation, not merely restate the generated Rust map. Rust-generated
vectors and mutation corpora bind the executable relation to the model, while residual universal
compiler/proof-system/hash assumptions remain explicit.

Finally, after disk admission opens, produce two fresh maximum-shape proofs in independent clean
run roots. Retain the canonical proof bytes, statement/action fixture, source revision, build
manifest, profile, security certificate, prove/verify timings, and SHA-512 digests. Restart-verify
both artifacts, replay the end-to-end mutation and fresh-node suites, run the formal/release gates,
then and only then authorize the profile and report measured proof bytes. Retained-artifact
authority uses fixed SHA-512 relation/release-manifest digests; any SHA-256 checksum is merely an
optional transport diagnostic and cannot authorize the profile.

## Concrete Steps

Run all commands from `/Users/pldd/Projects/Reflexivity/Hegemon`.

Inspect state without mutating it:

    git status --short --branch
    df -h .
    rg -n "SmallWood|Poseidon|BLAKE2b|SHA-512|SHAKE|tx_leaf" \
      circuits/transaction circuits/transaction-core protocol/kernel consensus node/src/native

Run focused lightweight tests as components land, selecting exact package/test names from the
source rather than broad workspace builds. Examples include:

    cargo test -p transaction-circuit smallwood_blake2b384 --lib
    cargo test -p transaction-circuit smallwood_shake256_full_relation --lib
    cargo test -p hegemon-node conventional_smallwood --lib

These commands are illustrative until the landed source defines the exact test identities. Check
`df -h .` immediately before any Cargo command. Do not run a command that triggers a proof build or
large dependency rebuild while available space is below 28 GiB.

When admitted, run the source-bound proof measurement command recorded by the final harness and
expect it to write into a unique disposable run root. Copy only qualifying final artifacts into the
checked-in retained-artifact directory; do not retain Cargo targets or transient traces.

Run formal and release checks only after their source gates exist:

    bash scripts/check_formal_crypto.sh --isolation-only
    bash scripts/check_formal_core.sh
    python3 scripts/check_release_crypto_profile.py
    python3 scripts/check_ci_release_gate_policy.py

The exact full release command list must be updated here from the implemented harness before
authorization.

## Validation and Acceptance

Acceptance requires one conventional-hash profile to pass every item below in the same source
revision:

1. The architecture tournament shows no smaller qualifying implemented candidate.
2. Independent standard KATs for every selected conventional primitive and adversarial trace
   mutations pass for the exact mixed full relation; retained rejected-profile KATs remain
   tournament evidence only.
3. The exact full two-input/two-output relation passes all sixteen masks, stablecoin cases, all
   authorization modes, and every public-binding mutation.
4. The complete-proof simulator and leakage tests cover every proof component; no witness-dependent
   distribution is omitted.
5. Independent exact-integer accounting gives strictly more than 128 bits after all composed
   PQ/QROM terms.
6. Two independently generated maximum-shape proof artifacts exact-decode, canonical-reencode,
   verify after restart, and retain identical statement/action semantics.
7. The same proof bytes survive wallet, RPC, relay, mempool persistence, mining, block, sync, reorg,
   and fresh-node validation; caches, receipts, aggregates, and sidecars have no authority.
8. Every targeted mutation rejects before state change, including cross-network and cross-version
   replay, proof/statement rewrapping, ciphertext and balance drift, nullifier and Merkle drift,
   intent drift, truncation, trailing bytes, and noncanonical encodings.
9. Lean semantic/refinement gates, Rust conformance, formal isolation, CI policy, binary primitive
   audit, release manifest, and retained-artifact manifest all pass.
10. Production remains fail-closed until items 1--9 pass; after authorization, deleting or mutating
    any required artifact closes the release gate again.

The minimized proof byte count is the length of the unchanged canonical proof carried by the
transaction, measured from the retained artifact. Envelope/action/block bytes are reported
separately and cannot be substituted for proof bytes.

## Idempotence and Recovery

All source and test changes must be additive until the replacement profile passes its gates. Keep
the existing production authorization unchanged while developing the candidate. Focused tests and
certificate generators must write to unique temporary directories and be safe to rerun. If a worker
lands overlapping edits, stop, inspect the exact diff, and integrate manually without overwriting
either worker or user changes. Never use reset, checkout, clean, or recursive deletion on this dirty
worktree. Any proposed cleanup that could remove material data requires explicit user approval.

## Artifacts and Notes

The final retained directory must contain, at minimum, two proof files, their canonical statements
and actions, a machine-readable measurement ledger, the exact security certificate, mutation and
restart-verification transcripts, the source revision and dirty-source digest, compiler/toolchain
versions, and a manifest hashing every retained byte. A retained artifact is evidence only for the
exact source/profile/certificate tuple in its manifest.

Historical 87.5--93.3 KiB SmallWood measurements and weak Binius/M4 proof sizes are comparison
inputs, not accepted artifacts for this plan. Static formulas, gate counts, and projected bytes are
not measurements.

## Interfaces and Dependencies

The SHAKE relation compiler must expose a deterministic trace constructor, a constraint verifier,
a lossless 56-byte digest projection, and exact gate/row accounting. The transaction relation must
consume typed hash-domain identifiers and expose one source of truth for its 893-byte public
statement and witness schedule. The proof wrapper must exact-decode, canonical-reencode, and return
a borrowed or owned slice containing the same proof bytes; it must not accept a sidecar identifier
in place of those bytes.

The security certificate must use exact integer or rational arithmetic and bind all parameters,
domains, hashes, retry rules, and proof-shape constants. The production authorization checker must
consume the retained-artifact manifest and formal/refinement results; no boolean supplied by a
caller may stand in for verifier acceptance or evidence availability.

No new ECC, pairing, RSA, Poseidon-authority, trusted-setup, receipt-authority, aggregation-authority,
or cache-authority dependency is permitted.

Revision note: Created on 2026-08-22 to integrate the architecture tournament and five inherited
worker streams under one fail-closed shipping contract.
