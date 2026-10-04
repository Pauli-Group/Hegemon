# Standalone SHAKE256 binary transaction proofs

This ExecPlan is a living implementation document maintained according to `.agent/PLANS.md`. It replaces the rejected block-aggregate plan. Hegemon does not activate a shielded transfer merely because this plan exists; activation requires every gate below.

## Purpose / Big Picture

Implement one wallet-generated, self-contained zero-knowledge proof per shielded transaction. The exact proof bytes admitted by a peer are the bytes included by a miner and reverified during block import, sync, reorg, and fresh replay. No block proof, proof-of-proof, receipt, cache result, or off-chain proof blob may substitute for it.

The conventional-hash profile uses fixed-layout SHAKE256 with 56-byte semantic outputs and a 64-byte proof transcript/commitment digest. The 448-bit semantic output has a generic quantum-collision exponent near 149 bits, leaving composition margin above the strict 128-bit target while two children plus a short fixed domain tag still fit one 136-byte SHAKE256 rate block. The proof relation is binary-native. Poseidon and the existing Goldilocks SmallWood relation are not active fallbacks.

## Progress

- [x] Rejected the off-block leaf/block-aggregate topology.
- [x] Measured current Binius, Flock, and SmallWood/Keccak lower bounds.
- [x] Restored the self-contained-proof invariant in README, DESIGN, and METHODS.
- [x] (2026-08-19) Implemented the `HEG-S4V2` fixed-layout SHAKE256-448 semantic transcripts, typed outputs, scalar vectors, and exact native Pay1x2 core relation. The depth-32 relation is 40 Keccak-f permutations and rejects 30 named adversarial mutations.
- [x] (2026-08-19) Implemented a strict 12-byte direct-proof envelope prototype with a 1 MiB full-envelope cap and exact route/length/trailing rejection.
- [x] (2026-08-19) Implemented the 478-byte `HGS2` canonical statement adapter with fixed shape/version/profile identity, two SHAKE256-448 ciphertext hashes, a typed SHAKE256-448 chain/genesis/rules binding, a public-derived SHAKE256-448 balance tag, exact decoding, and 28 mutation cases.
- [x] (2026-08-19) Implemented a real pinned-Binius SHAKE256 parent proof and measured a 40-permutation proof-geometry proxy. The proxy is not the complete Pay1x2 relation.
- [x] (2026-08-19) Implemented a fail-closed composed strict-PQ128 profile and byte calculator. The executable scaffold selects 264 classical bits because a 259-bit starting point floors at only 126 modeled post-quantum bits after QROM loss and the protocol-term union bound. It does not claim that upstream implements the selected profile.
- [x] (2026-08-19) Implemented a fail-closed benchmark harness with an 8 GiB live free-space reserve and frozen prototype-only reports.
- [x] (2026-08-19) Implemented and measured the complete Pay1x2 binary circuit: authorization, native-only policy, 61-bit ranges, ripple-carry conservation, all 40 SHAKE permutations, and all 478 canonical statement bytes. The ordinary precommit layout produces a 380,496-byte weak-profile proof plus a 12-byte envelope.
- [x] (2026-08-19) Composed exact `HGSP` parsing, prospective V5/Delta family-1/action-7 projection, authoritative action/network-to-HGS2 reconstruction, public-vector construction, and exact Binius verification. Seven malformed-envelope classes reject before projection, fifteen malformed-action classes reject before proof work, and fresh proofs over forged ciphertext-hash, network-binding, and balance-tag fields raw-accept but composed-reject against the original action/network.
- [x] (2026-08-19) Applied the explicit-private-input patch to a hash-guarded disposable copy of the exact full circuit. The real rate-3 proof is 350,800 bytes plus the 12-byte envelope, saving 29,696 bytes (7.80%) without changing the 1,883,192 relation rows or any acceptance gate.
- [x] (2026-08-19) Measured the cumulative direct precommit/mask co-commitment layout under the sealed evaluator. The full Pay1x2 proof is 309,072 bytes plus the 12-byte envelope, with every fixed relation, action, envelope, mutation, exact-consumption, and fresh-forgery gate passing. This was the first sealed prototype-only frontier.
- [x] (2026-08-21) Implemented and measured the cumulative terminal-message optimization. It commits and serializes the canonical inverse-NTT terminal message, re-encodes it under the identical Gao-Mateer domain in the verifier, and re-optimizes the FRI fold schedule. The full supervised Pay1x2 run produced a 272,176-byte canonical proof plus the 12-byte envelope, 36,896 bytes (11.94%) below the prior verified frontier. Every fixed relation, action, envelope, mutation, exact-consumption, carry/range, and fresh-forgery gate passed. The retained one-entry trial chain has head `1735398a62f5fe058d8909ff263201eba49655f5d3e87a22234269c16594a720`.
- [x] (2026-08-21) Replaced independent Merkle paths with a canonical compact frontier and measured a 249,520-byte proof plus the 12-byte envelope. Query indices alone determine the sorted leaf and sibling schedule; the verifier authenticates the unchanged roots before restoring query multiplicity.
- [x] (2026-08-21) Omitted FRI leaf scalars already fixed by preceding fold claims and reconstructed complete leaves before hashing. The full supervised Pay1x2 proof is **244,240 bytes plus the 12-byte envelope**, with every frozen verification gate passing. The current trial entry is `51c94235a189fcbf826f1fb387ccfb5bf78876d41bb90839619971346d0fb6ed`.
- [x] (2026-08-21) Built the native-word M4 **Pay1x2 core experiment** as one main circuit with no numbered chips. It binds that experiment's 2,448-byte witness and 478 public bytes, inlines 40 Keccak-f permutations, and compiles to 24,160 AND constraints in a `2^15` committed tier. Cumulative transparent-wire compression measures 65,440 proof bytes plus the 12-byte envelope. This is a non-ZK, 96-bit/SHA-256/GF(2^128), one-input/native-only geometry record, not the complete production relation or a frontier point.
- [x] (2026-08-21) Installed the fail-closed production frontier gate under `prototypes/standalone-shake256-binius/production-frontier-gate/`. Admission now requires six separately content-addressed and sealed-policy-allowlisted certificates, all bound to the candidate source and a live digest of the production proof surface: exact full 2-in/2-out production semantics, action/network/version binding, complete full-witness zero knowledge, composed PQ128/QROM security, two retained exact-parsed clean proof artifacts, and closed Lean/deployed-verifier differential refinement. The 65,440-byte M4 Pay1x2 point fails this gate with zero verified certificates, so the **accepted production frontier is empty**; its size remains geometry evidence only.
- [x] (2026-08-21) Implemented domain-separated SHAKE256-512 leaf, node, and Fiat-Shamir hashing and exercised it through the real Pay1x2 M4 prover/verifier. The exact rate-two proof is 149,360 bytes and rejects public, proof, and trailing mutations. It remains rejected because the transcript is transparent and its algebraic profile is still GF(2^128)/96-bit.
- [x] (2026-08-21) Implemented and independently cross-checked `E384 = GF(2^128)[Y]/(Y^3+Y+1)` over the pinned GHASH base field, including Frobenius irreducibility, multiplication, inversion, serialization, B128-to-E384 lifting, coefficient-lane reconstruction, multilinear folding/evaluation, exact 48-byte materialization counters, and a product-ring negative control. This is a mixed-field IOP seam, not a strict backend; pinned BaseFold/FRI still cannot consume it.
- [x] (2026-08-21) Implemented the true degree-two `GhashSq256b` alternative with two domain-separated E256 streams over one actual n15 B128 Merkle table. Thirteen dependency-free Rust tests and an independent manifest rebuild the field/table KATs and exact-consumed wire: 257,808 bytes for shared q=264 full paths and 512,544 bytes for the independent union. These are arithmetic/transport KATs, not compact PCS or product-soundness evidence; every binding, ZK, QROM, and frontier flag remains false.
- [x] (2026-08-21) Mapped the exact pinned E256/BaseFold implementation seam. Low-level FRI already admits extension values over base-field twiddles, but all higher IP/IOP channels, BaseFold/Merkle compilers, and M4 entry points couple committed symbols, claims, messages, and challenges to one field. A correct B128-commitment/E256-algebra backend therefore needs a new mixed channel and two-lane later-round PCS; a global E256 type swap widens the input commitments and changes M4 packing. No small type-coherent patch exists.
- [x] (2026-08-21) Implemented and independently audited the characteristic-two local HVZK sumcheck kernel. Fresh full-extension masks span the exact affine fiber of each linear or quadratic round, giving visible TV zero in exhaustive small fields and B128/E384 differential cases. Its canonical E384 wire is `48*linear_rounds + 96*quadratic_rounds` bytes with no explicit terminal delta. Missing/restricted/reused masks and a revealed delta have TV one, and an unbound terminal admits a false-sum forgery, so complete-ZK remains false until the global mask source, terminal relation, PCS/FRI/Merkle, outer proof, and QROM composition are bound and simulated.
- [x] (2026-08-21) Mapped and exactly priced the published Diamond ZK BaseFold plus DP24 degree-two ring-switch route. Although `(B128,GhashSq256b)` fits the algebra, two independent n15 branches require a 227,392-byte shared salted input opening and a 1,172,480-byte declared-wire skeleton. Sharing the immutable root and union authentication saves 20,480 bytes; reusing the query set is not permitted to square proximity soundness. Diamond does not prove ZK ring switching or higher-PIOP composition, so the published route is excluded from the compact target.
- [x] (2026-08-21) Added a canonical strict-transcript context before statement observation. The context binds the pinned backend revision, inline circuit identity, HGS2 statement/circuit/crypto/backend/profile IDs, hash profile, exact B128 modulus/basis/serialization fingerprint, framed relation-source digest, and inverse-rate log. Wrong-rate and prospective-E384-context replays reject. Raw upstream M4 verification remains outside this boundary and is not release-authorized.
- [x] (2026-08-21) Rejected the 317,312-byte wrapped-M4 experiment as zero-knowledge evidence. Its 128 appended satisfiable random rows do not mask the clear trace-evaluation claim for every verifier point: all appended rows share five high address bits, so a verifier challenge can annihilate their contribution. The artifact is deleted and the recorded measurement is `frontier_eligible=false`.
- [x] (2026-08-21) Rejected the first source-level constant-shift trace-claim transform. M4's ring-switch transparent tensor sums to `eq_r_double_prime[0]`, not one, so the old `s + k` equation is algebraically false for almost every honest transcript and becomes annihilable if changed to `s + k*c` without excluding `c=0`. The patch remains only as a rejected artifact and must not be compiled, measured, or admitted. The replacement must use the exact coefficient and transcript-symmetrically guarantee it is nonzero, or prove a grouped trace/precommit opening.
- [x] (2026-08-21) Added an executable strict refold/PCS byte-and-soundness model. The verifier now reconstructs and observes the terminal checksum at its original Fiat--Shamir position instead of receiving the redundant two-element message, saving exactly 96 bytes. The 112,784-byte Ligerito core is only a non-ZK Pay1x2/n14 model with unfrozen active-symbol provenance. Unfrozen n15 is 117,488 bytes only with an inadmissible 32 GiB encoded oracle and 133,200 bytes under the 512 MiB cap; n16 is 144,496 bytes with a 64 GiB oracle and 168,688 bytes under the cap. None is a frontier point.
- [x] (2026-08-21) Froze and independently re-audited the scalar maximum relation. It enforces zero production value balance, the exact 9-accept/7-reject activity-mask matrix, nonzero enabled stablecoin issuance, and commitment-bound `NoteKind` lineage across explicit accumulator initialization, approval, value-lock creation, and final-threshold modes. This closes the scalar native-mint and forged-threshold-state attacks, but is not M4 or production-admission evidence until the fixed-slot action adapter and compiled circuit enforce the same rules.
- [x] (2026-08-21) Implemented the prospective fixed-slot V5/Delta action and direct-envelope source boundary for the maximum relation. The exact 853-byte statement, two fixed input and output slots, authoritative stable-policy snapshot/CAS token, exact 2,147-byte wallet-v3 Gamma DA ciphertext parser/re-encoder, 512-KiB total envelope cap, and the derived public intent are reconstructed before proof verification. `FullProofBinding` v3 owns the exact 912-byte M4 public transport (`853 statement || 3 zero padding || 56 derived intent`) so a backend cannot independently substitute the externalized intent words. This is source-only until the disk-gated Cargo and composed-backend tests run.
- [x] (2026-08-21) Added the exact Lean maximum-relation specification under `formal/lean/Hegemon/FullShakeRelation/`. Lean 4.32.2 with warnings-as-errors checks the 9/7 masks, fixed slots, duplicate-nullifier rejection, zero value balance/no mint, nonzero stable issuance, all five typed authorization transitions and exploit regressions, and the exact 853-byte/56-byte grammar without `sorry`, `admit`, or axioms. SHAKE, Rust/M4 refinement, complete ZK, E384, and PQ128 remain explicit missing certificate fields; the formal result alone cannot populate the production frontier.
- [x] (2026-08-21) Implemented the source-level one-main/no-chip M4 realization of the maximum relation. It maps 671 private words and 114 verifier-owned public words, inlines all four note commitments, two nullifiers, two depth-32 paths, two spend KDFs, and the multiplexed five-mode authorization schedule. Public balance-tag and intent hashes are recomputed by the sealed composed verifier; retaining two independent final Merkle hashes preserves literal scalar acceptance. The resulting fixed source geometry is 83 Keccak-f calls. It has not yet been compiled or measured because free disk is below the 28-GiB heavy-run gate.
- [x] (2026-08-21) Added an independent allocation-free maximum-relation geometry counter and applied four audited rewrites to the live M4 prototype: direct packed-public/cached-balance decoding, an MSB-select Merkle ordering cone with XOR recovery of the other child, exact one-hot authorization SHAKE-frame muxing, and selected-policy structural deduplication that preserves both approval-state lanes. The frozen patch chain and 262,247 deterministic checks tighten the conservative syntactic upper from 65,336 to 60,788 hidden words, at most 30,394 active B128 symbols, and at least 2,374 unused n15 symbols. Independent review found no relation change, collision assumption, or caller-trust shortcut. This is not a compiled-size claim because CSE/fusion/DCE can change the realized delta; n15 and every padding-capacity result remain conditional until the disk-gated compile and differential run freeze the exact active prefix.
- [x] (2026-08-21) Added and independently clean-stack checked the grouped cross-oracle BaseFold Phase-A source patch. It removes the separately serialized precommit component claim, proves one aggregate precommit/private wiring relation, retains independent per-oracle masks and reduced evaluations, bridges exactly one aggregate scalar through prover/builder/replay/verifier, and leaves Phase B unchanged. The post-coefficient patch is SHA-256 `37dfdee589e476c09fe5c955bd46942cd5aa293a3177d7a43d07f14aeb8ef9df`; its source-static checker passes. It remains uncompiled B128 weak-profile mechanics, not complete-ZK or strict-security evidence.
- [x] (2026-08-21) Compiled and retained an exact full-maximum-M4 SHAKE256-400 proof-size experiment. The source-bound canonical envelope is **1,344,828 bytes** (`3 * 448,224`), SHA-256 `0ce525a6c790e1be4c47cf6d482b767f455616f06e5ab013d561378d6ab81a56`, 281,568 bytes (17.31%) below the SHAKE256-512 baseline. The 853-byte statement, 83 Keccak-f calls, 51,449 AND constraints, restart verification, exact-consumption, mutation, and fresh-forgery gates are unchanged. The 133.332424-bit result is an arithmetic screen only; complete adaptive ZK, B128-query soundness composition, and a sequential direct-product QROM theorem remain open, so production and formal-security flags stay false.
- [x] (2026-08-21) Added and corrected the fail-closed strict n15 mixed-PCS byte/theorem screen. It now uses the required 64-byte SHAKE256-512 proof commitments rather than the 56-byte semantic-digest width. At rate `1/8`, four-symbol leaf packing lowers the E384 first-level screen from 146,656 to 136,496 bytes; a 32-byte opened-leaf salt makes it 140,560. Paired-E256 grouped-and-salted screens are 117,088 bytes at rate `1/16` and 99,328 bytes at rate `1/32`. The old 56-byte rows are demoted as non-strict. All residual budgets remain model-only because salt hiding, mixed-field extraction, characteristic-two ZK ring switching, complete simulation, parallel RBR extraction, and composed QROM are unproved.
- [x] (2026-08-21) Implemented, corrected, and adversarially tested the random-high-coefficient hiding screen for the surviving E256-by-two path. The fixed-matrix B128-linear rank criterion is now also mechanized in Lean with exact reused-padding and zero-rank failures. A source patch fills every whole unused n15 trace symbol with fresh randomness and uses the same buffer for the commitment and shift reduction, but exact observation provenance is still missing and the shift path is generally F2-linear rather than B128-linear. Complete ZK therefore requires a binary-basis observation sink and verifier-bound GF(2) rank audit rather than the old scalar-row shortcut.
- [x] (2026-08-21) Replaced the random-padding byte placeholder with an executable SHAKE256-512/E256 FRI topology and exact parser. The honest toy is 2,736 bytes but its exported matrix is non-ZK (padding rank four, joint rank eight). The actual n15 q=33 one-round serializer is 118,192 bytes with separate fold trees and 89,744 bytes in the maximum-overlap combined-tree screen. One round is not a low-degree proof: all fifteen degree-halving rounds have a 325,424-byte structural floor, or 387,427 bytes under exact per-tree classical salt diagnostics, before the production PIOP and complete security terms. Twenty-five tests pass; no row is a candidate or frontier point.
- [x] (2026-08-21) Screened STIR as the closest recursive proximity alternative. Its smallest complete theorem-shaped transport is 403,392 bytes, while deleting every Merkle authentication node still leaves 128,456 bytes, 4,388 over the raw cap. Published STIR also assumes smooth multiplicative prime-field domains and does not prove the additive characteristic-two, mixed B128/E256, two-branch, adaptive-QROM construction. Fourteen tests pass and every authority flag remains false.
- [x] (2026-08-21) Formalized the exact conditional parallel-product requirement. Two history-conditional `2^-132` extraction errors multiply to `2^-264` over one immutable shared commitment, but domain separation or marginal bounds alone do not establish those premises. The current branches lack six pointwise extraction/coin-independence obligations plus ROM/QROM composition, so their apparent half-budget security cannot be used.
- [x] (2026-08-21) Exhaustively screened the transparent VOLE/MPC-in-the-head family against the complete M4 nonlinear surface. The valid generic VOLEitH term is 6,374,400 bytes for 3,187,200 Boolean ANDs; treating 49,800 lane-word ANDs as field multiplications is rejected. The Keccak-specific checkpoint construction lowers the nonlinear vector but its best strict forest is 1,632,012 bytes, and private-witness replication alone is 171,776 bytes. Nine executable model/parser tests pass; this family is not a compact candidate under the screened constructions.
- [x] (2026-08-21) Rejected the affine binding-vector shortcut against the nonlinear maximum M4 relation. Masked BitAnd requires three cross-term products per gate; the optimistic n15 joint trace/mask opening is 288,408 raw bytes under the 28-GiB oracle cap, and the paired-E256 screen is 280,056 bytes. The old 113,904-byte affine wire remains only a parser/simulator negative control and cannot enter the frontier.
- [ ] Compile and differentially verify the complete maximum-shape M4 relation through the concrete `FullProofVerifier`; Pay1x2-only measurements cannot enter the frontier.
- [ ] Implement a complete end-to-end zero-knowledge M4 transcript/compiler. BaseFold trace-oracle masking and the grouped Phase-A repair close specific clear-linear leaks but are insufficient. The remaining construction must prove the full joint distribution of the trace/precommit commitments and openings, Libra endpoint, BaseFold/FRI/Merkle queries, and correlated multiplication endpoint, fail closed outside the exact one-main surface, and provide a complete simulator/composition proof over the actual strict challenge field.
- [ ] Implement the strict SHAKE256-512/wide-challenge proof backend and a reviewed end-to-end zero-knowledge/composed-QROM argument.
- [ ] Remove the 6,080-byte outer artifact and activate the direct proof envelope under a fresh version/rules hash.
- [ ] Measure maximum-shape strict-profile proof bytes, prover time, verifier time, and memory.
- [ ] Set block capacity from the measured canonical artifact and complete the fresh-version cutover.

## Surprises & Discoveries

- Observation: a fixed SHAKE256-448 Merkle parent is exactly 133 absorbed bytes, not 96 bytes. The frame is eight profile bytes, eight role bytes, one field-count byte, two two-byte lengths, and two 56-byte children. SHAKE padding still keeps it to one Keccak-f permutation.
  Evidence: the V2 scalar and binary implementations share the KAT `025d0bf7d9a82b06b8ac7ba85247a34d90b26d41184dc2f0a1bff7d851fe7f8b112a5ba5519c7177a465a3d1c1b07faf9abaf808bae80dce`.
- Observation: Pay1x2 needs 37 semantic invocations but 40 Keccak-f permutations. Three note commitments consume two permutations each; the co-KDF, nullifier, and 32 Merkle parents consume one each.
  Evidence: the scalar executable reports `absorbed_bytes=5153`, `keccak_f=40`, and a 1,536,000 chi-multiplication floor.
- Observation: the real one-parent proof is 242,336 bytes at inverse-rate log 3 and the 40-independent-parent proxy is 384,208 bytes. The actual network-bound full Pay1x2 circuit is 380,496 bytes at the same rate, compiles to 1,883,192 rows, and stays in the `2^21` bucket.
- Observation: moving fixed witness-source bits from the precommit oracle to the existing private oracle is implementable because no Fiat-Shamir challenge separates those commitments. The exact full Pay1x2 rate-3 proof falls from 380,496 to 350,800 bytes; rates two and four measure 381,200 and 355,856 bytes, so rate three remains the local optimum.
- Observation: the sealed cumulative co-commit layout reduced the proof to 309,072 bytes. Sending the terminal Reed-Solomon codeword was then the largest redundant wire component: the verifier can reconstruct it injectively from the committed inverse-NTT message. Committing and serializing the message instead produced a measured 272,176-byte proof, 7,552 bytes below the original rate-three static estimate.
- Observation: the terminal-message implementation required three concrete corrections before measurement: retain `log_inv_rate` in the size estimator, compute the terminal encoding inputs before consuming the prover in `finalize(self)`, and use the reference inverse butterflies over the production NTT's identical domain because the optimized `NeighborsLast` implementation intentionally omits `inverse_transform`. The inverse runs only over the small terminal vector; the large forward NTT remains optimized.
- Observation: canonical Merkle frontiers and verifier-known FRI values reduce the terminal-message envelope from 272,188 to 244,252 bytes. The latter saves exactly 5,280 bytes by omitting distinct selected field positions across three FRI trees while reconstructing the full committed leaves before hashing. These optimizations do not reduce the 1,883,192 relation rows, so further scalar-wire tuning cannot approach a 122,126-byte half-size target.
- Observation: native 64-bit M4 changes the relation tier rather than merely compressing the scalar wire. Forty Keccak permutations plus all Pay1x2 semantics require 24,160 native AND constraints and a `2^15` committed tier. The cumulative selected wire, deterministic main-public message elision, division-free terminal-target leaves, and verifier-known zero suffix measure 65,440 proof bytes at inverse-rate log four, 56,674 envelope bytes below the requested half-size threshold.
- Observation: M4's main public segment is genuinely verifier-bound, while the hidden batch-commit layout applies only to numbered chips. The implementation therefore keeps every Keccak inline in a single main circuit and requires `VerifierTranscript::finalize()` for exact proof consumption.
- Observation: switching only the M4 trace oracle to BaseFold masking is not an end-to-end zero-knowledge transform. Witness-dependent sumcheck and shift-reduction messages remain serialized, while the masked oracle adds approximately 44,976 bytes at the selected rate. This path is rejected as both incomplete and larger.
- Observation: naively widening every serialized proof field element to 48 bytes gives a 1,997,712-byte strict-profile projection even after that optimization. A sub-1-MiB strict backend therefore needs compact committed symbols with wide algebraic challenges, not indiscriminate element widening.
- Observation: adding random satisfiable circuit rows is not a zero-knowledge compiler. In the rejected wrapped-M4 experiment, five shared high address bits let a verifier point erase every appended-row mask contribution; even the honest Fiat-Shamir bad-event estimate is about `2^-125.68`, below the target. A valid repair must mask every clear witness-dependent functional with full rank for every challenge and prove simulation, not count random rows.
- Observation: the compact strict-PCS problem is now separated from Pay1x2 reward hacking. The executable n14 Ligerito figure is relation-specific and non-ZK. Production n15/n16 resource-capped models exceed the byte cap before a complete ZK wrapper, so a production win requires a materially different mixed-field vector PCS or a smaller verified maximum-relation circuit, not a more favorable label on the same model.
- Observation: a concrete source-only n15 binding-vector PCS screen rejects ordinary SHAKE-Merkle openings at 86,656 bytes, 49,340 bytes over the 37,316-byte budget left by the compact refold algebra. A 37,296-byte proposal-only target has only 20 bytes of headroom and has no binding, hiding, complete-ZK, or strict-security proof; it is not a construction or frontier point. The next PCS pass must either supply those missing properties in executable form or prove the target impossible.
- Observation: sharing the last hash of two Merkle paths is not a literal scalar-circuit optimization when the scalar relation admits distinct SHAKE preimages with the same root. The source briefly reached 82 permutations by equating the two final preimages, then reverted to two independent root hashes and 83 permutations rather than silently adding a collision-freedom premise to the relation.
- Observation: the maximum-relation source likely remains in n15, but the random zero tail is not yet known. A pinned static counter proves only a 100-to-9,174-symbol interval; using the convenient 6,768-symbol midpoint as if it were compiled geometry would be reward hacking. Random-padding ZK is admissible only after exact compilation and a full-rank audit over every opened, terminal, fold, and auxiliary functional.

## Decision Log

- Decision: preserve one unchanged wallet proof per transaction and reject block aggregation as consensus authority.
  Rationale: this preserves witness privacy, independent mempool admission, censorship resistance, and fresh-node replay without an unavailable side channel.
  Date/Author: 2026-08-19, Codex.
- Decision: implement a specialized native-asset one-input/two-output profile first.
  Rationale: ordinary payments must not pay for inactive consolidation, stablecoin, multisig, or universal-branch constraints.
  Date/Author: 2026-08-19, Codex.
- Decision: retain Hegemon's 61-bit monetary bound and zero-nullifier padding reservation.
  Rationale: the fresh prototype must not silently enlarge the monetary domain or invent unrelated zero-byte restrictions.
  Date/Author: 2026-08-19, Codex.
- Decision: widen the spend secret, note randomness, and rho to 384 bits in `HEG-S4V2`.
  Rationale: a 256-bit secret has only exactly 128 bits of generic Grover work and drops the composed model to about 127.541 bits when unioned with the proof terms. The wider inputs restore search margin without adding a Keccak permutation.
  Date/Author: 2026-08-19, Codex.
- Decision: use SHAKE256-448 semantic outputs and target SHAKE256-512 proof hashing.
  Rationale: 448-bit semantic outputs have a generic quantum-collision exponent near 149 bits and still permit one-permutation binary Merkle parents.
  Date/Author: 2026-08-19, Codex.
- Decision: keep 512 KiB as an optimization target and 1 MiB as a hard parser/resource cap.
  Rationale: capacity follows the measured proof; a backend over the cap fails rather than weakening security or outsourcing proof authority.
  Date/Author: 2026-08-19, Codex.

## Outcomes & Retrospective

The prototype milestone now has executable SHAKE semantics, a mutation-tested Pay1x2 relation, an exact direct envelope, authoritative prospective action/network composition, real scalar and native-word full-circuit proof roundtrips, cumulative wire compression, frozen measurements, and fail-closed security/frontier calculators. It demonstrates that the standalone conventional-hash architecture is technically real without Poseidon or aggregation. The 65,440-byte proof plus 12-byte envelope is a weak-profile geometry measurement, not an accepted frontier point. The accepted production frontier is empty because the point proves only Pay1x2, is transparent, uses upstream's nonqualifying 96-bit/SHA-256/GF(2^128) profile, retains no two exact proof artifacts, and lacks closed production semantic/deployed-verifier refinement. The attempted 317,312-byte wrapped-M4 proof is also rejected because its ad-hoc appended rows do not establish zero knowledge. Strict transcript context binding and an executable E384 coefficient-lane seam now exist, but no mixed-field IOP/PCS or complete simulator argument does. The next implementation target is the complete production relation followed by end-to-end zero knowledge and a compact wide-challenge strict backend; no proof-size result is promotable before all six production certificates pass.

The main optimization lesson is structural: the 40-permutation relation already has approximately 1.54 million irreducible chi multiplications and occupies a `2^21` proof-system bucket. Work should target oracle layout, reviewed commitment batching, and compact base-field committed symbols while retaining wide challenges. Lower security, reduced-round Keccak, hidden off-proof checks, or an aggregate side channel are not acceptable byte optimizations.

## Context and Orientation

`circuits/standalone-shake256-prototype/src/lib.rs` owns the prospective scalar semantic grammar. Every semantic output is 56 bytes. Its fixed profile tag is `HEG-S4V2`; roles include note commitment, nullifier, and Merkle node. One SHAKE call derives an ordered 56-byte authorization key and 56-byte nullifier key from the 48-byte spend secret. Per-note rho and commitment randomness are also 48 bytes.

`circuits/standalone-pay1x2-relation-prototype/src/lib.rs` owns the exact scalar relation: one native-asset input, one recipient output, one mandatory change output, a depth-32 hidden path, 61-bit value and fee bounds, exact conservation, derived spend authority, a nonzero nullifier, and public anchor/nullifier/output-commitment/fee bindings. The balance tag belongs to the future canonical-statement adapter and is not another hidden-note hash.

`circuits/standalone-proof-envelope-prototype/src/lib.rs` owns the prospective canonical wire. Its 12-byte header is `HGSP`, version `u16`, backend `u8`, profile `u8`, and little-endian proof length `u32`; the remainder is the unchanged proof. Exact decoding rejects unsupported routes, short, trailing, truncated, empty, and oversized forms before backend work.

`circuits/standalone-pay1x2-statement-prototype/src/lib.rs` owns the prospective action-to-statement boundary. Its exact 478-byte `HGS2` grammar binds statement/circuit/crypto/backend/profile identity, the fixed one-input/two-output native shape, core relation fields, two ordered SHAKE256-448 hashes of canonical ciphertext bytes, a SHAKE256-448 binding of exact chain-id/genesis/rules inputs, and a SHAKE256-448 balance tag derived only from public fields. Its prospective V5/Delta family-1/action-7 type fixes counts, sizes, native balance slots, absent optionals, network binding, and binding digest. The full prototype observes the complete encoding in Fiat-Shamir and the composed verifier recomputes it from authoritative action and network inputs before proof work.

`prototypes/standalone-shake256-binius/backend` is a nested Cargo workspace pinned to Binius64 revision `3f96163049f680b2909f6545690bd929f1b48c44`. It implements a complete bit-level Keccak-f[1600] SHAKE256-448 parent circuit and direct IronSpartan roundtrip. Its 40-parent mode is deliberately labeled a geometry proxy.

`prototypes/standalone-shake256-binius/pay1x2-backend` joins the exact 40-permutation relation to the 478-byte statement and authoritative composed envelope verifier. Its ordinary-layout frozen rate sweep is 574,000/413,008/380,496/382,992 proof bytes for inverse-rate logs one through four. `prototypes/standalone-shake256-binius/all-private-patch` contains the applyable pinned-upstream and full-relation layout patches and the exact full-circuit rate-two/three/four measurements 381,200/350,800/355,856 bytes. `prototypes/standalone-shake256-binius/m4-full-pay1x2-prototype` owns the exact single-main native-word circuit and its stock 109,264-byte minimum. `m4-selected-wire-patch`, `m4-public-elision-patch`, and `m4-terminal-target-patch` freeze the preceding steps; `m4-padding-fiber-patch` freezes the current 65,440-byte raw-proof minimum.

`.agent/hardening/binius-pq128-proof-size/strict_pq_profile.py` is an executable parameter gate, not a security proof. `scripts/measure_standalone_shake256_prototype.py` validates backend JSON, measures wall time and peak resident memory, enforces disk and byte caps, computes block capacity, and rejects the upstream security profile unless a prototype-only override is explicit.

## Product invariants

1. The wallet never discloses note openings, spend keys, hidden paths, values, or prover randomness to a miner.
2. A peer validates the complete transaction before relaying it.
3. A miner needs no specialized aggregation step and includes the same canonical proof bytes.
4. A fresh node validates the chain from canonical block data alone.
5. Local parallel or batch verification must return the conjunction of the independent results and cannot change canonical bytes.
6. The proof is transparent and has a checked composed post-quantum security bound of at least 128 bits.

## Measured baseline and consequence

The existing 520-transfer geometry permits at most 124,080 artifact bytes per transaction. No measured conventional-hash backend meets that limit:

- Binius64 wrapped ZK starts at 298,304 bytes under an insufficient 96-bit/SHA-256 profile.
- Earlier direct IronSpartan measurements start at 246,048 bytes. Upstream describes its direct masked-oracle protocol as zero knowledge, but Hegemon has not established end-to-end zero knowledge for the exact transaction relation.
- Flock's 70-Keccak Slim transcript is 133,599 bytes while non-ZK and only 100-bit; widening only its Merkle digests to 48 bytes gives 142,271 bytes.
- Binius M4 for the 64-permutation membership floor is 128,544 bytes while non-ZK and only 96-bit, before the rest of the relation.
- Goldilocks SmallWood can fit approximately one Keccak permutation under the cap; one hidden depth-32 path projects to at least 632,502 bytes even under an unrealistically favorable checkpoint model.

Therefore 520 transfers per 64 MiB block is a stretch target, not a launch invariant. Security and the self-contained transaction model do not move. With 4,967 non-proof bytes per action, the exact block capacity is:

    floor((67,108,864 - 2,525) / (4,967 + measured_proof_bytes))

Reference ceilings are 126 transactions for a 512 KiB proof and 63 for a 1 MiB proof. The first implementation has a 1 MiB parser/resource hard cap and a 512 KiB optimization target. A proof above 1 MiB rejects the backend rather than expanding blocks.

## Cryptographic profile

Semantic transcripts use SHAKE256 with fixed, uniquely registered short domain tags and exact field order. Semantic output is 56 bytes. A binary Merkle parent hashes one fixed tag plus two 56-byte children in one 136-byte-rate absorption. Proof commitments and Fiat-Shamir use 64-byte SHAKE256 output. The 56-byte transaction semantic types are distinct from both Poseidon limbs and 48-byte BLAKE2b consensus identifiers.

The proof profile selects at least 264 classical soundness bits before the modeled quantum reduction and union of protocol errors. A 259-bit starting point is recorded only as a rejected lower bound: under the executable scaffold it floors at 126 post-quantum bits after the dominant proof terms are union-bounded. The calculator also charges generic Grover search for spend-key recovery, note-commitment hiding randomness, and rho privacy; 256-bit inputs would reduce the composed result below 128, so V2 requires 384-bit entropy for each. Algebraic challenges use a field/extension large enough for the maximum relation degree and the composed QROM calculation; GF(2^128) is not release-authorized. The calculation is a parameter gate, not a security reduction; release still requires the implemented backend and its proof to justify every term.

## Relation and wire optimization

- Use the direct IronSpartan path as the starting proof architecture, not the transparent M4 proof and not the high-fixed-cost wrapped-ZK path. Treat zero knowledge as an explicit end-to-end theorem and implementation gate; no upstream mode name substitutes for that evidence.
- Implement a fixed `Pay1x2` profile for the normal one-input/two-output payment path and a separately versioned consolidation profile. Do not make every payment pay for unused universal branches.
- Use the SHAKE256 rate directly: the fixed 133-byte Merkle-parent frame plus padding requires one permutation.
- Combine each input's authorization PRF and nullifier derivation in one domain-separated XOF transcript where the semantics permit it.
- Reconstruct all public statement bytes from the canonical action; observe them in Fiat-Shamir rather than duplicate them inside the proof.
- Replace `NativeTxLeafArtifact` with a fixed-version direct proof envelope. This saves exactly 6,080 bytes without changing authority.
- Co-commit equal-length proof oracles and use canonical Merkle multiproofs only after a separate soundness proof and mutation suite; this is a proof-wire optimization, not aggregation.
- Use canonical two-path Merkle sharing when paths overlap; worst-case admission remains the disjoint-path size.
- Keep ciphertext hashing and deterministic balance-tag reconstruction outside the relation only when the exact values are recomputed from proved public fields and observed by the proof transcript.

Note commitments, nullifiers, hidden membership, spend authorization, ranges, per-asset conservation, stablecoin equality, and active/padding constraints remain proved.

## Plan of Work

### 1. Exact statement and hash registry

Add the fresh typed SHAKE semantic types/domains and an independent scalar transaction evaluator. Generate positive and one-field-at-a-time negative vectors. No consensus route activates.

### 2. Binary relation

Pin one reviewed Binius64 fork. Implement `Pay1x2` first, then the consolidation profile. Differentially compare the circuit with the scalar evaluator across valid randomized witnesses and every semantic mutation.

### 3. Strict security profile

Replace the upstream 96-bit, SHA-256, GF(2^128) profile. Produce an exact byte-accounting report and a machine-checked composed security report. Any uncounted protocol error or upstream caveat fails closed.

### 4. Direct canonical envelope

Add a fresh proof/version tag and strict decoder. The action contains the proof, not a reference. Reject old, short, trailing, wrong-profile, noncanonical, or oversized forms before expensive work.

### 5. End-to-end gates

Benchmark wallet proving, peer verification, maximum-shape block import, 64 MiB block selection, sync, restart, and reorg. Instrument all proof copies and parser allocations. Set the active action count from the measured artifact size using the equation above.

### 6. Formal and release authorization

Retarget the action-to-statement refinement, deployed verifier boundary, zero-knowledge statement, QROM bridge, and block composition to the exact standalone proof. Activate only under a fresh rules hash/genesis after independent cryptographic and implementation review.

## Concrete Steps

From the repository root, run the scalar and relation checks with disposable targets:

    CARGO_TARGET_DIR=/private/tmp/hegemon-shake-semantics-target CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 cargo test --manifest-path circuits/standalone-shake256-prototype/Cargo.toml --locked
    CARGO_TARGET_DIR=/private/tmp/hegemon-pay1x2-relation-target CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 cargo test --manifest-path circuits/standalone-pay1x2-relation-prototype/Cargo.toml --locked
    CARGO_TARGET_DIR=/private/tmp/hegemon-pay1x2-relation-target CARGO_INCREMENTAL=0 cargo run --manifest-path circuits/standalone-pay1x2-relation-prototype/Cargo.toml --locked --quiet

The relation run must report 2,448 private-witness bytes, 232 core-statement bytes, 37 invocations, 5,153 absorbed bytes, 40 Keccak-f calls, 1,536,000 chi multiplications, and `mutation_summary rejected=30/30`.

Run the envelope, parameter, and harness tests:

    CARGO_TARGET_DIR=/private/tmp/hegemon-envelope-target CARGO_INCREMENTAL=0 cargo test --manifest-path circuits/standalone-proof-envelope-prototype/Cargo.toml --locked
    CARGO_TARGET_DIR=/private/tmp/hegemon-statement-target CARGO_INCREMENTAL=0 cargo test --manifest-path circuits/standalone-pay1x2-statement-prototype/Cargo.toml --locked
    python3 .agent/hardening/binius-pq128-proof-size/test_strict_pq_profile.py
    python3 scripts/test_measure_standalone_shake256_prototype.py

The envelope and statement-adapter suites must pass nine and ten tests. The Python suites currently pass ten and nine tests respectively.

Reproduce the real parent proof only when at least 16 GiB is free:

    df -h /private/tmp
    CARGO_TARGET_DIR=/private/tmp/hegemon-binius-prototype-target CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 cargo +1.97.1 build --release --locked --manifest-path prototypes/standalone-shake256-binius/backend/Cargo.toml
    python3 scripts/measure_standalone_shake256_prototype.py --allow-unsupported-prototype --min-free-gib 16 -- /private/tmp/hegemon-binius-prototype-target/release/hegemon-standalone-shake256-binius-backend
    python3 scripts/measure_standalone_shake256_prototype.py --allow-unsupported-prototype --min-free-gib 16 -- /private/tmp/hegemon-binius-prototype-target/release/hegemon-standalone-shake256-binius-backend --parents 40 --rate 3 --deterministic-test

Expected frozen measurements are 242,336 proof bytes for one parent and 384,208 bytes for the 40-independent-parent proxy. Both reports must say `mode: prototype_only`, never `strict`.

Reproduce the complete Pay1x2 circuit with the same disk gate:

    CARGO_TARGET_DIR=/private/tmp/hegemon-pay1x2-binius-target CARGO_INCREMENTAL=0 CARGO_PROFILE_RELEASE_DEBUG=0 cargo +1.97.1 run --release --locked --offline --manifest-path prototypes/standalone-shake256-binius/pay1x2-backend/Cargo.toml -- --rate 1 --rate 2 --rate 3 --rate 4 --deterministic-test

The selected proof must be 380,496 bytes, the full envelope 380,508 bytes, and the report must identify a 478-byte public statement, 1,883,192 compiled rows, the network-source mutation gates, and unsupported release security.

Reproduce the optimized full circuit from the exact frozen source hashes and clean pinned Binius checkout:

    prototypes/standalone-shake256-binius/all-private-patch/run-full-pay1x2.sh /private/tmp/binius64-api-3f961630

The rate-two/three/four proofs must be 381,200/350,800/355,856 bytes, the selected full envelope must be 350,812 bytes, every composed envelope/action/fresh-forgery/relation gate must pass, and the runner must remove its exact temporary source and target directories on exit.

## Validation and Acceptance

The prototype milestone is accepted when the scalar SHAKE KAT matches the binary gadget, the Pay1x2 valid fixture accepts, all 30 semantic mutations reject, the exact envelope rejects all route/length/trailing mutations, the real proof roundtrip verifies, changed public output/proof/trailing proof reject, benchmark JSON validates, and the strict calculator rejects the current upstream backend.

Production activation has the following additional gates:

- Maximum standalone artifact is at most 1 MiB; target at most 512 KiB.
- Composed post-quantum security is at least 128 bits, rounded down.
- Proof is zero knowledge for the exact maximum relation.
- Proof remains byte-identical across wallet, relay, block, sync, reorg, and restart.
- A fresh node performs no network fetch beyond canonical block data to validate it.
- Maximum proof verification and parser work are bounded before admission.
- No aggregate, receipt, cache, or sidecar can authorize a transaction.
- Production manifest, rules hash, vectors, Rust, reference evaluator, and Lean projections agree exactly.

## Idempotence and Recovery

All prototype crates are nested workspaces and do not modify the root dependency graph or activate consensus. Tests and measurements are repeatable. Use task-specific targets under `/private/tmp`, check free space before a Binius build, and delete only that exact disposable target afterward. Never run a broad `cargo clean` while the shared workspace is active. If a proof run is interrupted, remove its exact temporary target and rerun from the pinned lockfile.

## Artifacts and Notes

Component reports live in `prototypes/standalone-shake256-binius/backend/measurements`. The one-parent report records 242,336 proof bytes and 242,348 envelope bytes. The V2 40-parent proxy records 384,208 proof bytes and 384,220 envelope bytes. Ordinary-layout Pay1x2 reports live in `prototypes/standalone-shake256-binius/pay1x2-backend/measurements`: the proof is 380,496 bytes and the envelope is 380,508 bytes. The all-private Pay1x2 report is `prototypes/standalone-shake256-binius/all-private-patch/full-pay1x2-measurement-2026-08-19.json` at 350,800 proof bytes. The selected scalar-wire trial remains under `prototypes/standalone-shake256-binius/selected-value-patch/`. The latest transparent Pay1x2 geometry record is frozen in `prototypes/standalone-shake256-binius/m4-padding-fiber-patch/full-pay1x2-padding-fiber-2026-08-21.json`: 65,440 proof bytes and a 65,452-byte envelope with every direct M4 verification gate passing. It has no production-frontier status.

The strict-profile scaffold reports approximately 129.415 modeled post-quantum bits at 264-classical-bit protocol budgets, but its capability flags remain false until implementation and independent review evidence exist. The current upstream negative control remains rejected.

## Interfaces and Dependencies

The scalar semantic crate exposes `SemanticDigest`, typed note/nullifier/Merkle/key wrappers, `encode_frame`, `hash_fields`, `derive_spend_key_material`, and `evaluate_pay1x2`. The scalar relation exposes `Pay1x2Witness`, `Pay1x2Statement`, `derive_statement_unchecked`, and `verify_relation`. The envelope exposes an exact borrowed decoder and `verify_envelope_exact` over a backend `ProofBinding` interface. The Binius prototype imports the scalar crate for cross-check tests and pins all upstream proof dependencies by exact Git revision.

Any production backend must accept canonical reconstructed statement bytes plus the exact direct proof and return only accept/reject. It must not accept a receipt, cache key, aggregate, or proof reference. It must publish an exact profile digest committing to the relation, transcript, commitment scheme, field/challenge construction, security parameters, wire grammar, and semantic registry.

Revision note (2026-08-19): recorded the executable scalar, prospective V5/Delta action projection, 478-byte network-bound adapter, exact composed envelope verifier, complete Pay1x2 Binius circuit, measured full-circuit private-oracle optimization, security calculator, and benchmark milestones; corrected the Merkle frame to 133 bytes and the security start to 264 bits; and documented the naive strict-profile size consequence.

## Outcome

This path preserves Hegemon's purpose and gives up only the unsupported 520-transfer launch claim. Proof size, rather than an arbitrary transaction count, determines initial capacity. Subsequent proof-wire improvements raise capacity without changing consensus authority or privacy.
