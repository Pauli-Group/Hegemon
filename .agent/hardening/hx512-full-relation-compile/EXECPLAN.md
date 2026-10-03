# Freeze the disqualified inactive HX512 diagnostic relation

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept current. It follows `.agent/PLANS.md`.

## Purpose / Big Picture

The repository needs an honest retained record of the attempted `HX512B01` successor relation. A reviewer can run dependency-free Python checks and see its canonical statement, verifier context, private witness, 2-input/2-output diagnostic interpreter, all-W64 cap-16 manifest membership, ciphertext binding, conventional BLAKE2b schedule, and deterministic odd-field cost projection. The same artifact must reproduce the accepted counterexamples that disqualify this language: permissionless positive stablecoin issuance even in an active native-route shape, a noncumulative epoch cap, and an arbitrary anchor when no input is active. It therefore claims neither an exact full production relation nor numeric sparse-R1CS lowering, a final proof profile, a proof, complete zero knowledge, QROM security, Rust/formal refinement, measured proof bytes, or production authorization.

## Progress

- [x] (2026-08-22) Read `AGENTS.md`, `.agent/PLANS.md`, the README whitepaper, and the transaction-proof, hash, ledger, and stablecoin portions of `DESIGN.md` and `METHODS.md`.
- [x] (2026-08-22) Inspect the frozen `HX448C02` odd-field macro compiler and finalized all-W64 manifest-authority artifact.
- [x] (2026-08-22) Reconcile core `HX512B01` frames with the frozen specialized `HGMAIDV2`/`HGMAROOT` all-W64 authority schedule; generic authority frames are rejected.
- [x] (2026-08-22) Implement the isolated canonical statement/context/witness parser and executable semantic interpreter.
- [x] (2026-08-22) Implement a streaming RFC 7693 BLAKE2b-512 evaluator for all 90 calls and 213 fixed compressions without materializing a 29-million-row matrix.
- [x] (2026-08-22) Evaluate all 160 diagnostic mask/mode/stablecoin cells: 66 current-language acceptances and 94 structural rejections, including policy version zero.
- [x] (2026-08-22) Constant-fold every fixed RFC parameter/personalization block, remove all 270 inconsistent parameter-NOT rows, and recount the diagnostic projection as `m=29,509,887`, `n=21,531,579`, `l=9,704`, and `nnz=123,197,556`.
- [x] (2026-08-22) Reproduce and retain the three production-blocking accepted counterexamples; record that a sound repair requires a fresh grammar, profile, state transition, and consensus refinement.
- [x] (2026-08-22) Compare the diagnostic mask language to active native admission: bit order is `i0,i1,o0,o1`; diagnostic acceptance is 33/80, while the live 1..2-input and 1..2-output intersection is 26/80 with per-mode counts `9,6,2,6,3`; active binding construction fixes `value_balance=0`.
- [x] (2026-08-22) Reclassify the descriptor and statement rules hash as test-only diagnostic values; leave every proof-system identity and final consensus rules hash null/unallocated and reject every legacy V6/K64 identity.
- [ ] Emit and retain the canonical relation manifest, certificate, and mutation corpus.
- [ ] Run dependency-free checkers and tests; preserve every authority, ZK, QROM, refinement, release, and production flag as false.

## Surprises & Discoveries

- Observation: the first semantic-suite draft and the finalized all-W64 authority artifact agree on width, cap, row, path, and compression count but not on hash bytes. The authority artifact hashes direct messages with exact 16-byte RFC 7693 personalization, while the draft suite wraps those values in the `HX512B01` frame.
  Evidence: `.agent/hardening/manifest-authority-closure/README.md` specifies `HGMAROOT` personalization, while `.agent/hardening/hx512-semantic-suite/hx512_suite.py` initially specified 80/235/149-byte framed policy/leaf/node messages.

- Observation: anonymous primitive multiplicities and row counts do not constitute an executable relation because they contain no source operands, witness constructor, or row evaluator.
  Evidence: the first independent red-team pass accepted 410 of 1,141 statement bytes and 6,209 of 11,000 witness bytes under XOR-01 mutation. The replacement semantic interpreter rejects all 12,213 baseline byte mutations and retains named residuals for every semantic family, while continuing to state that numeric R1CS wire IDs and sparse A/B/C rows are absent.

- Observation: the exact V2 verifier context is `manifest_root64 || parent_height:u64le`, not `snapshot64 || height`; the statement state root is independently the personalized snapshot hash of height and manifest root. Policy version zero is valid in the V2 Rust language.
  Evidence: the inactive kernel V2 canonical encoder and verifier checks use this layout, and the corrected source suite includes a version-zero positive fixture.

- Observation: the selected all-W64 row authenticates policy configuration but does not authorize a mint or evaluate its collateral ratio. `max_mint_per_epoch` is compared only to one transaction magnitude.
  Evidence: the diagnostic interpreter accepts a mode-0 mask-13 transaction with one ordinary input, one ordinary change output, and one new stablecoin output without an issuer/collateral opening. Two cap-one transactions under the same parent root and height both accept while their cumulative issuance is two.

- Observation: the diagnostic activity table and value-balance language do not match the active native transfer route.
  Evidence: `node/src/native/admission.rs::validate_transfer_action_payload` requires nonempty bounded nullifier and commitment vectors, reducing the diagnostic 33 mask/mode pairs to 26 live-shape pairs. `binding_hash_matches` constructs `value_balance: 0`, while the diagnostic statement accepts a general signed magnitude.

## Decision Log

- Decision: allocate no production identity and reuse neither `HX448C01` nor `HX448C02`; consume the semantic suite's fresh test-only identity after its source is final.
  Rationale: a relation identity must bind one exact grammar and hash program, and rejected identities cannot be reinterpreted.
  Date/Author: 2026-08-22 / Codex.

- Decision: import the frozen odd-field primitive compiler rather than copying its R1CS primitive library.
  Rationale: this minimizes duplicate source while keeping every macro expansion, sparse-row rule, and field encoding source-pinned.
  Date/Author: 2026-08-22 / Codex.

- Decision: retain a compact cost-projection macro program plus a separate executable diagnostic interpreter and streaming hash evaluator, but describe neither as a sparse-R1CS compiler or full relation.
  Rationale: the red team demonstrated that anonymous multiplicities cannot bind witness semantics. Neither component assigns all numeric intermediate wire IDs nor emits sparse A/B/C coordinates, and the language itself has accepted production counterexamples. The `29,509,887` rows are therefore only a deterministic cost projection for the disqualified diagnostic grammar.
  Date/Author: 2026-08-22 / Codex.

- Decision: do not execute the planned three selected exhaustive Boolean traces after the semantic gate failed.
  Rationale: evaluating 87,149,376 bit rows cannot rehabilitate a language that already accepts counterfeits. The certificate records zero executed exhaustive rows, the planned count, and the disqualification reason.
  Date/Author: 2026-08-22 / Codex.

- Decision: make `statement.rules_hash` a diagnostic SHA-512 descriptor checksum only, with every fresh arithmetization, packing, PCS, IOP, DECS, ZK tape, transcript, and wire field null.
  Rationale: the required wide-ZK SmallWood profile is not frozen, and rejected SMZ2/SWV6/K64 identities cannot be reallocated. A final consensus rules hash cannot exist before both the repaired relation and proof wire freeze.
  Date/Author: 2026-08-22 / Codex.

- Decision: pin the inactive kernel V2 module/checker/tests, but bind the shared `protocol/kernel/src/lib.rs` only through the exact export line `pub mod stablecoin_manifest_authority_v2;` and an absent/duplicate check.
  Rationale: the shared module registry has unrelated concurrent edits; a whole-file hash would create false drift while an exact line contract binds this integration seam.
  Date/Author: 2026-08-22 / Codex.

## Outcomes & Retrospective

Work is in progress. The attempted `HX512B01` language is disqualified and is being frozen only as diagnostic evidence. The existing `HX448C02` source relation remains a negative baseline. No route or production module has been edited.

## Context and Orientation

`circuits/transaction/src/full_blake2b448_relation.rs` is the frozen scalar schedule for the 869-byte `HX448C02` diagnostic. `prototypes/standalone-shake256-binius/m4-full-blake448-e384-candidate/src/mixed_candidate.rs` is its source-level M4 relation-family graph. `.agent/hardening/hvzk-whir-odd-field-r1cs/compiler.py` lowers that graph to deterministic odd-field R1CS macros over Goldilocks without retaining expanded matrices. It leaves four predicates host-only.

`.agent/hardening/manifest-authority-closure/` defines the finalized prospective all-W64 row: exactly 215 bytes, at most 16 rows ordered strictly by numeric `(asset_id, policy_version)`, and a depth-four Merkle witness containing a u32 index, selected row, and four 64-byte siblings. `.agent/hardening/hx512-semantic-suite/` defines the fresh 64-byte semantic roles, statement, widened witness, conventional hashes, and fail-closed security ledgers. This artifact composes those two sources with the frozen transaction schedule.

The verifier context is not prover authority. It is the authenticated parent manifest root and parent height supplied by the verifier. The semantic relation constrains the recomputed manifest root and height to equal that context, independently reconstructs the statement snapshot/state root as the personalized hash of height and manifest root, reconstructs the selected policy identity and manifest path, and checks lifecycle, oracle freshness, dispute, issuance, and cap predicates. Authentication of that context by the native verifier remains unrefined and false.

## Plan of Work

Create `compiler.py` in this directory. It must strict-import and SHA-512 pin the frozen primitive compiler, final semantic suite, and final manifest authority files. It must define exact parsers for the statement, verifier context, and private witness; reject trailing bytes, wrong magic/version/network/domain/action fields, noncanonical booleans, nonzero transport padding, and legacy-width reinterpretations. It must emit inherited transaction groups for all 16 masks and all five authorization modes, 64-byte note/nullifier/Merkle/intent/balance/ciphertext links, the exact conventional hash program, and the new manifest/state groups.

The four former host-only mutations must reject in the diagnostic interpreter: forged policy identity, forged selected row/path membership, forged reconstructed manifest/state root, and forged verifier context root/height. Ciphertext mutations must be tied to the exact 2,147-byte slots. The canonical manifest must also retain the three accepted production counterexamples and the 33-versus-26 active-route grammar mismatch. It records projected `m`, `n`, `l`, auxiliary-variable count, matrix nonzero count, Section 11 power-of-two projection, diagnostic descriptor digest, and source-set digest, while explicitly marking every full-relation, sparse-lowering, proof, security, refinement, and production claim false.

Create `test_compiler.py` with parser, field-row, mask/mode, hash KAT, manifest path, ciphertext, host-forgery, geometry-ledger, source-pin, artifact-canonicality, and fail-closed capability tests. Generate `relation_manifest.json`, `certificate.json`, and `mutation_corpus.json` only through the compiler's canonical JSON writer.

## Concrete Steps

From `/Users/pldd/Projects/Reflexivity/Hegemon`, run only dependency-free commands:

    PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/hx512-full-relation-compile/compiler.py --write
    PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/hx512-full-relation-compile/compiler.py --check
    PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/hx512-full-relation-compile/test_compiler.py
    git diff --check -- .agent/hardening/hx512-full-relation-compile

Do not run Cargo, rustc, Lake, a proof build, or an expanded-matrix generator while the disk gate is closed.

## Validation and Acceptance

Acceptance requires exact canonical artifact readback, all parser and mutation tests passing, all 160 diagnostic mask/mode/stablecoin cells classified as 66 accepted and 94 rejected, all three accepted production counterexamples reproduced, the live-route recount fixed at 26 accepted and 54 rejected with per-mode counts `9,6,2,6,3`, every former host-only forgery rejected by the diagnostic interpreter, ciphertext mutations rejected, all 5,940 call digests across the 66 diagnostic positives matching independent `hashlib`, constant-folded parameter KATs matching all eight fixed initial states, and geometry recomputed from the macro ledger. The expensive 87,149,376-row selected bit trace must remain unexecuted because the semantic gate failed. Every full-relation, production, proof, security, refinement, and sparse-lowering flag is false; `proof_bytes` and retained proof artifact fields remain null.

## Idempotence and Recovery

Artifact generation is deterministic and overwrites only files in this isolated directory. The checker computes expected bytes in memory before comparison. A source-pin mismatch fails before writing. No cleanup, checkout, reset, production registry edit, or route activation is permitted.

## Artifacts and Notes

The final handoff will record SHA-512 hashes for the compiler, tests, generated manifest, certificate, and mutation corpus, plus the relation's domain-separated SHAKE256-512 digest.

## Interfaces and Dependencies

`compiler.py` must load the frozen primitive compiler through `importlib` and use its `Program`, primitive rows, sparse-row validator, Goldilocks modulus, and mask/mode table. It must load the semantic suite for final identity, frame schedule, layouts, KATs, and W64 source constructors. It must independently source-pin the finalized manifest-authority report and capability ledger so the row/cap/path contract cannot drift silently.

Revision note (2026-08-22): reclassified the attempted successor as a disqualified diagnostic after retaining permissionless-mint, noncumulative-cap, no-input-anchor, and active-route-grammar counterexamples; removed the post-gate exhaustive trace from acceptance and made every final proof/consensus identity explicitly unallocated.
