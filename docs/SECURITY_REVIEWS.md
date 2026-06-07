# Security Reviews, Cryptanalysis, and Audit Integration

This document defines how we commission third-party reviews for the post-quantum primitives, integrate their findings, and keep the repository’s verification artifacts plus adversarial test harnesses aligned with proof-of-work (PoW) miner operations.

## 1. Commissioning miner identity and pool cryptanalysis

We currently rely on:

- **ML-DSA-65** (Dilithium3 profile) for miner rig identities, pool controller signatures, and block announcements.
- **SLH-DSA** (SPHINCS+-SHA2-128f) for long-lived trust roots and protocol-release artifact signing.
- **ML-KEM-1024** (Kyber) for encryption and key agreement on miner <-> pool control channels.
- **Poseidon2-384** inside the STARK AIR for commitments/nullifiers/Merkle hashing (48-byte digests), plus SHA-256/BLAKE3 externally for protocol hashes and identifiers.

Commissioning requirements:

1. **Parameter validation brief** – Hand vendors `DESIGN.md §1` plus `crypto/README.md` (if updated) and request:
   - Side-channel considerations for deterministic RNG wrappers used in `crypto::ml_dsa`/`ml_kem`, with explicit coverage of rack-level miners that share chassis power/temperature envelopes.
   - State-of-the-art lattice reduction cost estimates for ML-DSA-65 and ML-KEM-1024 under BKZ 2.0 and dual attacks with quantum sieving assumptions, highlighting replay risk if pool identities are rotated slowly.
   - Hash/collision resistance assessments for Poseidon2 parameters/constants and the 48-byte commitment/nullifier/Merkle encodings used across circuits and pallets (see `circuits/transaction-core/src/poseidon2_constants.rs` and `circuits/transaction-core/src/hashing_pq.rs`).
2. **Deliverables** – Require a written report with:
   - Attack models and concrete security estimates (bits) for each primitive plus explicit call-outs on miner impersonation or pool takeover implications.
   - Annotated diff suggestions mapped to function names (e.g., `crypto::hashes::poseidon::permutation`).
   - Test vectors or scripts to reproduce any exploit, especially those that would let an attacker spoof PoW share telemetry or tamper with block templates mid-flight.
3. **Tracking** – Log every finding using the JSON template in §4 and reference them inside `DESIGN.md`/`METHODS.md` with the finding ID.
4. **Cadence** – Trigger a review whenever:
   - Upgrading parameter sets (e.g., bumping to ML-DSA-87 for miner identities).
   - Touching STARK hash parameters or note commitment definitions that govern share proofs.
   - NIST publishes errata or usage guidance affecting FIPS 203/204/205 or SP 800-227 KEM handling.
   - Annually, even without code changes, to capture new cryptanalytic results relevant to mining pools.

## 2. Third-party audit scopes

We separate audit scopes into three tracks so teams can bid independently:

| Track | Scope | Entry materials | Exit criteria |
| --- | --- | --- | --- |
| Cryptography | `crypto/`, `circuits/transaction`, `circuits/block` | `DESIGN.md §1`, `METHODS.md §1-3`, formal specs under `circuits/formal/` | All proofs verified, parameter justifications signed off, new issues filed. |
| Protocol / PoW coordination | `consensus/`, `protocol/`, `network/` | `DESIGN.md §2-4`, `consensus/spec/`, `consensus/spec/formal/` | PoW admission-control limits confirmed, miner share forgery tests documented, consensus doc updated with mitigations. |
| Implementation & pool ops | `wallet/`, `network/`, `state/`, CLI tooling, `runbooks/` | `METHODS.md` operational sections, `runbooks/` | Continuous security tests pass on patched builds; new regression tests added for each finding with miner/pool reproduction steps. |

## 2.1 Formal PQ Soundness Review (QROM)

Engineering estimates (see `SECURITY.md`) are sufficient for “ship and measure”, but external claims of “128-bit post-quantum soundness” require a tighter, cited argument. This track is the scope for that work.

Concrete steps and deliverables:

1. **Freeze the exact protocol transcript** – Document the full non-interactive proof transcript: which objects are committed (trace, preprocessed trace, Merkle roots), which challenges are derived (and in what order), and what hash/permutation is used. Reference the concrete code paths in `circuits/*/src/p3_config.rs` and verifiers (`circuits/*/src/p3_verifier.rs`).
2. **State the security model precisely** – Specify what is modeled as an oracle/permutation (e.g., Fiat–Shamir hash as a random oracle in the QROM; Poseidon2 as an ideal permutation or as a concrete primitive with best-known bounds), and what the adversary can query.
3. **Bound statistical IOP soundness** – Use the cited FRI/DEEP-FRI/ALI literature to derive a concrete upper bound for the soundness error of the exact protocol variant we implement (including blowup factor, query count, and any DEEP/ALI composition parameters as used by Plonky3).
4. **Account for Fiat–Shamir in the QROM** – Apply a QROM-secure Fiat–Shamir theorem appropriate for this proof system and write down the loss terms in terms of the number of oracle queries and the number of challenge rounds.
5. **Account for commitment/hash binding in the quantum setting** – Bound the commitment/Merkle binding advantage in terms of the collision resistance of the sponge (capacity-based bounds and best-known quantum collision algorithms).
6. **Compose the final bound** – Write the final “soundness error ≤ ε_total” statement as a sum of explicit terms (IOP + FS transform + hash binding). Translate that bound into “bits” via `-log2(ε_total)` under stated assumptions, and cross-check it against our engineering estimate.
7. **Publish a reproducible parameter report** – Add a small script or test that prints the exact parameters used by each circuit (capacity/digest size, log_blowup, num_queries, etc.) so auditors can match the write-up to the code.
8. **Independent review** – Commission a third-party cryptography review specifically for the proof soundness write-up and record it in the finding log below.

Suggested starting references:

- Fiat–Shamir in the QROM: https://eprint.iacr.org/2014/587
- Post-quantum security of Fiat–Shamir: https://eprint.iacr.org/2017/398
- STARK construction / ALI context: https://eprint.iacr.org/2018/046
- DEEP-FRI: https://eprint.iacr.org/2019/336
- Quantum collision finding (collision problem): https://arxiv.org/abs/quant-ph/9705002
- Poseidon2: https://eprint.iacr.org/2023/323.pdf

Audit execution steps:

1. **Scope doc** – Provide auditors with this file and highlight specific commits/tags.
2. **Kickoff** – Walk auditors through the PoW-oriented model-checking specs and fuzz harnesses. Capture questions in `docs/SECURITY_REVIEWS.md#finding-log`.
3. **Remediation workflow** – Each finding becomes a GitHub issue linking to the affected file, severity, and recommended fix. Patches must include:
   - Test demonstrating the exploit before the fix (e.g., spoofed miner identity, pool payout tampering).
   - Update to `DESIGN.md` or `METHODS.md` describing the mitigation rationale and any impact on mining pool workflows.
4. **Integration** – After merging fixes, append a short summary to `DESIGN.md` (architecture impact) and to the relevant runbook.

## 2.2 Native Backend Lattice Review (verified-leaf aggregation + BK-MSIS)

The native backend review package under `audits/native-backend-128b/` is its own track. It is not the same thing as the Plonky3 QROM review above. Reviewers for this track should be given:

- `docs/crypto/native_backend_spec.md`
- `docs/crypto/native_backend_formal_theorems.md`
- `docs/crypto/native_backend_verified_aggregation.md`
- `docs/crypto/native_backend_commitment_reduction.md`
- `docs/crypto/native_backend_security_analysis.md`
- `audits/native-backend-128b/CLAIMS.md`
- `audits/native-backend-128b/REVIEW_QUESTIONS.md`
- the packaged `review_manifest.json`
- the packaged `current_claim.json`
- the packaged `attack_model.json`
- the packaged `message_class.json`
- the packaged `claim_sweep.json`
- the packaged `reference_verifier_report.json`
- the packaged `reference_claim_verifier_report.json`
- the packaged `production_verifier_report.json`

Scope split:

1. **Verified-leaf aggregation review** – Confirm that the shipped `receipt_root` lane really does replay every tx-leaf verification and every fold recomputation, and that the repo does not overstate this as CCS soundness.
2. **Exact reduction review** – Confirm that the deterministic-commitment collision game, exact live message subclass, conservative padded cap, and zero-loss coefficient flattening are stated correctly for the active parameter set.
3. **Concrete attack-model review** – Evaluate whether the chosen coefficient-space SIS estimate and conservative instance are the right attack model for the active quotient `Z_q[X] / (X^54 + X^27 + 1)`.

Required deliverables:

1. A written statement on whether the native fold layer is accurately described as verified-leaf aggregation rather than Neo/SuperNeo CCS soundness.
2. A written statement on whether the exact BK-MSIS reduction and coefficient flattening note are correct for the active implementation.
3. A written statement on whether the chosen estimator model is acceptable, too optimistic, or missing a stronger known attack path.
4. Reproduction notes using the packaged `review_manifest.json`, fixed vectors, and `native-backend-ref`.
5. Independent claim-recomputation notes using the packaged `attack_model.json`, `current_claim.json`, and `native-backend-ref verify-claim`.

Whenever the active native backend parameters, live witness schema, or claim model change, regenerate the package and attach the new `review_manifest.json` and `package.sha256` to the next external review request.

The native backend is release-gated as a candidate, not production-accepted crypto. CI and tag releases run:

```bash
./scripts/check_native_backend_release_posture.sh --package audits/native-backend-128b/native-backend-128b-review-package.tar.gz
```

That default gate requires `review_state = candidate_under_review`, `maturity_label = structural_candidate`, and no completed external-cryptanalysis flag in the packaged manifest. A future production acceptance must use `--require-accepted --acceptance-artifact <path>` and must include a checked-in external acceptance note; changing repo-local prose is not enough.

## 3. Formal verification & continuous security testing

- The mandatory release-facing formal gate is:

  ```bash
  bash scripts/check_formal_core.sh
  ```

  It builds the pinned Lean proof kernel under `formal/lean`, generates Lean bridge message-root/replay, bridge checkpoint-output canonical/journal bytes, bridge long-range proof-shape, bridge header-MMR opening-shape, bridge header-MMR parent/root transcript, bridge FlyClient sampling transcript/index, shielded-nullifier, consensus fork-choice, consensus PoW-admission, consensus header-preimage, consensus PoW miner-identity, consensus version-policy, consensus proof-policy, consensus native tx-leaf admission, consensus receipt-root admission, consensus recursive-block admission, consensus recursive public replay, consensus recursive semantic inputs, consensus DA-root byte binding, consensus proven-batch binding, consensus aggregation V5 header admission, supply-accounting, native action-ordering, native tx-leaf artifact, native receipt-root, transaction-balance, transaction Merkle-path, transaction public-input shape, transaction public-input binding, and transaction statement-hash conformance vectors and checks them against production Rust helpers, validates `config/formal-security-claims.json`, validates the blueprint DAG in `config/formal-security-blueprint.json`, checks the formal inventory, verifies independent bridge message/replay vectors in `testdata/formal_core_vectors/`, and reruns the existing native backend reference vectors in `testdata/native_backend_vectors/`.
- `formal/lean/Hegemon/Bridge/MessageRoot.lean` contains real Lean bridge message-root transcript theorems for exact domain/count/hash length-prefix bytes, invalid hash-length rejection, ordered-pair transcript construction, and reversed-pair transcript distinction. `formal/lean/Hegemon/Bridge/GenerateVectors.lean` emits transcript examples checked against the production `protocol-kernel` root preimage helper. Treat this as real but narrow evidence: it does not prove BLAKE3 cryptographic security or implementation equivalence, bridge light-client validity, external-chain covenant behavior, or full native-node equivalence.
- `formal/lean/Hegemon/Bridge/LongRange.lean` contains real Lean long-range proof-shape theorems for verifier-hash binding, message-count binding, header/MMR length shape, trusted/message/tip height ordering, message opening leaf/index/source binding, FlyClient sample height/opening-index agreement, confirmation policy, tip-work policy, and claimed-output agreement. `formal/lean/Hegemon/Bridge/GenerateLongRangeVectors.lean` emits examples checked against the production `consensus-light-client` helper called by the long-range verifier. Treat this as real but narrow evidence: it does not prove SHA-256 implementation equivalence, PoW hash security, MMR hash binding, FlyClient sampling soundness, external-chain covenant behavior, or complete bridge light-client soundness.
- `formal/lean/Hegemon/Bridge/CheckpointOutput.lean` contains real Lean checkpoint-output byte grammar theorems for the exact output domain, canonical-preimage/domain-plus-wire relation, fixed 404-byte journal tuple, scalar little-endian encodings, and max-scalar cases. `formal/lean/Hegemon/Bridge/GenerateCheckpointOutputVectors.lean` emits canonical and journal byte examples checked against production `consensus-light-client` output encoding and decoding helpers, including fixed-length rejection for truncated or trailing journal bytes. Treat this as real but narrow evidence: it does not prove BLAKE3 cryptographic security or implementation equivalence, bridge message-root/hash derivation, external-chain covenant behavior, or complete bridge light-client soundness.
- `formal/lean/Hegemon/Bridge/HeaderMmr.lean` contains real Lean header-MMR opening-shape theorems for peak decomposition, context mismatch rejection, leaf bounds, sibling-count admission, local-index derivation, and left/right path orientation. `formal/lean/Hegemon/Bridge/GenerateHeaderMmrVectors.lean` emits examples checked against the production `consensus-light-client` helper used by standalone and long-range MMR opening verification. Treat this as real but narrow evidence: it does not prove SHA-256 implementation equivalence, MMR parent/root hash security, FlyClient sampling soundness, external-chain covenant behavior, or complete bridge light-client soundness.
- `formal/lean/Hegemon/Bridge/HeaderMmrTranscript.lean` contains real Lean header-MMR parent/root transcript theorems for exact domain bytes, u32/u64 little-endian counters, left/right child order, ordered peak concatenation, empty roots, and reversed-peak distinction. `formal/lean/Hegemon/Bridge/GenerateHeaderMmrTranscriptVectors.lean` emits byte examples checked against the production `consensus-light-client` parent/root preimage helpers hashed by MMR construction and verification. Treat this as real but narrow evidence: it does not prove BLAKE3 cryptographic security or implementation equivalence, SHA-256 header-hash implementation equivalence, MMR collision resistance, full MMR hash binding, FlyClient sampling soundness, external-chain covenant behavior, or complete bridge light-client soundness.
- `formal/lean/Hegemon/Bridge/FlyClient.lean` contains real Lean FlyClient sampler theorems for exact domain-separated transcript bytes, u64/u32 little-endian range and sample-index encoding, digest-prefix modulo reduction, duplicate sample preservation, sample-count truncation, and empty/reversed range behavior. `formal/lean/Hegemon/Bridge/GenerateFlyClientVectors.lean` emits examples checked against the production `consensus-light-client` helpers used by long-range sample derivation. Treat this as real but narrow evidence: it does not prove BLAKE3 cryptographic security or implementation equivalence, probabilistic FlyClient sampling soundness, MMR hash binding, external-chain covenant behavior, or complete bridge light-client soundness.
- `formal/lean/Hegemon/Bridge/Replay.lean` contains real Lean replay-state theorems: `Hegemon.Bridge.stage_prevents_duplicate_pending`, `Hegemon.Bridge.import_prevents_reimport`, and `Hegemon.Bridge.import_prevents_restaging`. `formal/lean/Hegemon/Bridge/GenerateVectors.lean` emits examples checked against production `protocol-kernel` bridge encoding and `InboundReplayState` behavior. Treat this as real but narrow evidence: it does not prove BLAKE3 replay-key derivation, bridge light-client validity, external-chain covenant behavior, or full native-node equivalence.
- `formal/lean/Hegemon/Shielded/Nullifier.lean` contains real Lean nullifier-state theorems: `Hegemon.Shielded.stage_rejects_zero`, `Hegemon.Shielded.import_rejects_zero`, `Hegemon.Shielded.stage_prevents_duplicate_pending`, `Hegemon.Shielded.import_prevents_reimport`, and `Hegemon.Shielded.import_prevents_restaging`. `formal/lean/Hegemon/Shielded/GenerateVectors.lean` emits examples checked against production `protocol-shielded-pool::NullifierState` behavior. Treat this as real but narrow evidence: it does not prove full transaction balance conservation, note commitment correctness, AIR/proof-system soundness, or full native-node equivalence.
- `formal/lean/Hegemon/Consensus/PowRules.lean` contains real Lean PoW-admission theorems for compact-target rejection, strict timestamp admission, hash-threshold rejection, and fixed-width Work48 cumulative-work behavior. `formal/lean/Hegemon/Consensus/GeneratePowVectors.lean` emits examples checked against `consensus::pow` and `consensus-light-client` helpers. Treat this as real but narrow evidence: it does not prove SHA-256 implementation equivalence, retarget economics, network orphan policy, or long-range finality. Header preimage serialization is covered separately by `Hegemon/Consensus/Header.lean`.
- `formal/lean/Hegemon/Consensus/Header.lean` contains real Lean header-preimage theorems for the signing preimage domain and fixed-field byte layout, signing-preimage independence from signature/BFT bitmap/PoW seal payloads, BFT bitmap tag/length encoding, PoW seal tag/nonce/pow_bits encoding, and absent-auth tags. `formal/lean/Hegemon/Consensus/GenerateHeaderVectors.lean` emits exact byte preimages checked against production `BlockHeader::signing_preimage_v1` and `BlockHeader::full_header_preimage_v1`. Treat this as real but narrow evidence: SHA-256 cryptographic security and implementation equivalence, ML-DSA unforgeability, semantic correctness of header field values, retarget economics, and network finality remain separate review targets.
- `formal/lean/Hegemon/Consensus/MinerIdentity.lean` contains real Lean miner-identity theorems for PoW headers requiring no BFT signature bitmap, a registered miner key, exact ML-DSA-65 signature length, successful signature-byte parsing, and successful signature verification. `formal/lean/Hegemon/Consensus/GenerateMinerIdentityVectors.lean` emits examples checked against the production `PowConsensus` helper. Treat this as real but narrow evidence: ML-DSA cryptographic security, ML-DSA implementation correctness, and miner key custody remain separate review targets. Header signing preimage byte grammar is covered separately by `Hegemon/Consensus/Header.lean`.
- `formal/lean/Hegemon/Consensus/VersionPolicy.lean` contains real Lean version-policy theorems for initial bindings, activation/retirement boundaries, same-height retirement precedence, duplicate initial deduplication, and first unsupported transaction ordering. `formal/lean/Hegemon/Consensus/GenerateVersionPolicyVectors.lean` emits examples checked against the production `VersionSchedule::validate_versions` helper used by PoW and BFT import. Treat this as real but narrow evidence: social upgrade governance, manifest correctness, and per-version proof-system soundness remain separate review targets.
- `formal/lean/Hegemon/Consensus/NativeTxLeafAdmission.lean` contains real Lean native tx-leaf admission theorems for missing proof envelopes, tx_leaf envelope kind, native verifier-profile agreement, artifact size caps, receipt verifier-profile agreement, expected artifact-hash checks, and cache receipt plus public transaction-view agreement before backend verification or cache reuse. `formal/lean/Hegemon/Consensus/GenerateNativeTxLeafAdmissionVectors.lean` emits examples checked against the production consensus helper used by native tx-leaf verification, and a focused regression rejects stale cache reuse for a different transaction view. Treat this as real but narrow evidence: native backend proof soundness, native artifact parsing, statement-hash preimage binding, and BLAKE3 artifact-hash security/equivalence remain separate review targets.
- `formal/lean/Hegemon/Consensus/ReceiptRootAdmission.lean` contains real Lean receipt-root admission theorems for payload leaf/receipt count agreement, tx-validity claim agreement, transaction artifact availability, receipt_root envelope kind, native verifier-profile agreement, artifact size caps, tx-artifact count agreement, statement-commitment agreement, and verified leaf-count agreement. `formal/lean/Hegemon/Consensus/GenerateReceiptRootAdmissionVectors.lean` emits examples checked against the production consensus helpers used around native receipt-root verification. Treat this as real but narrow evidence: native tx-leaf proof soundness, native receipt-root byte parsing, native receipt-root cryptographic fold soundness, backend transcript challenge derivation, and BLAKE3 security/equivalence remain separate review targets.
- `formal/lean/Hegemon/Consensus/RecursiveBlockAdmission.lean` contains a real Lean theorem, `Hegemon.Consensus.RecursiveBlockAdmission.artifact_accepts_iff_preconditions`, proving the executable recursive-block artifact admission predicate for recursive_block_v1/v2 envelope kind, verifier-profile agreement, artifact decode success, recursive header-version agreement, tx-count agreement, statement-commitment agreement, and public-replay agreement before heavy recursive verification. The same kernel also proves `Hegemon.Consensus.RecursiveBlockAdmission.direct_v1_requires_semantic_replay` and `Hegemon.Consensus.RecursiveBlockAdmission.direct_v2_requires_semantic_replay`, pinning that the generic registry verifier fails closed unless the product path supplies verified-record semantic replay inputs. `formal/lean/Hegemon/Consensus/GenerateRecursiveBlockAdmissionVectors.lean` emits examples checked against the production `evaluate_recursive_block_artifact_admission` helper used by `ParallelProofVerifier` and the direct rejection in `RecursiveBlockVerifier`. Treat this as real but narrow evidence: native tx-leaf proof soundness, recursive proof cryptographic soundness, recursive semantic-input source binding except through the separate `RecursiveSemanticInputs` claim, BLAKE3 security/equivalence, aggregation STARK soundness, and complete block proof validity remain separate review targets.
- `formal/lean/Hegemon/Consensus/RecursivePublicReplay.lean` contains real Lean recursive public replay theorems for contiguous tx-index admission, gap/duplicate/decreasing-order rejection, v1/v2 semantic-field propagation, v1 message-root carriage, v2 message-root omission, and public tuple byte lengths. `formal/lean/Hegemon/Consensus/GenerateRecursivePublicReplayVectors.lean` emits examples checked against production `block-recursion` public replay helpers. Treat this as real but narrow evidence: BLAKE3/fold_digest48 security or implementation equivalence, recursive proof cryptographic soundness, native tx-leaf proof soundness, recursive semantic-input source binding except through the separate `RecursiveSemanticInputs` claim, aggregation STARK soundness, and complete block proof validity remain separate review targets.
- `formal/lean/Hegemon/Consensus/RecursiveSemanticInputs.lean` contains real Lean recursive semantic-input theorems for nonempty/nullifier/DA admission, rejection precedence, and source binding for expected statement commitment, parent/applied commitment-tree roots, kernel roots, nullifier root, DA root, header message root, and recursive tree-state commitments. `formal/lean/Hegemon/Consensus/GenerateRecursiveSemanticInputVectors.lean` emits examples checked against the production `recursive_block_semantic_inputs_from_block` helper used before recursive block verification. Treat this as real but narrow evidence: BLAKE3, DA erasure-code, Merkle tree hash, kernel-root hash, nullifier-root hash, and recursive-state-commitment cryptographic security or implementation equivalence, native tx-leaf proof soundness, recursive proof cryptographic soundness, consensus block-header validity, and complete block proof validity remain separate review targets.
- `formal/lean/Hegemon/Consensus/TreeTransition.lean` contains real Lean block tree-transition theorems for proof starting-root agreement, commitment application success, proof ending-root agreement, accepted applied-root return, and rejection precedence. `formal/lean/Hegemon/Consensus/GenerateTreeTransitionVectors.lean` emits examples checked against the production `verify_and_apply_tree_transition_without_anchors` helper used after block proof verification. Treat this as real but narrow evidence: commitment-tree hash security or implementation equivalence, note commitment correctness, native tx-leaf proof soundness, recursive proof cryptographic soundness, DA soundness, and complete block proof validity remain separate review targets.
- `formal/lean/Hegemon/Consensus/DaRoot.lean` contains real Lean DA-root byte/shard theorems for transaction ciphertext blob serialization, zero DA-param rejection, data/parity/total shard-count arithmetic, `da-leaf`/`da-node` preimage domains, child-order binding, and even/odd Merkle proof-step orientation. `formal/lean/Hegemon/Consensus/GenerateDaRootVectors.lean` emits examples checked against production `consensus::build_da_blob` and `state-da` shard/preimage helpers. Treat this as real but narrow evidence: Reed-Solomon correctness, BLAKE3 security or implementation equivalence, DA sampling probability, network chunk availability, and ciphertext sidecar availability remain separate review targets.
- `formal/lean/Hegemon/Consensus/ProvenBatchBinding.lean` contains a real Lean theorem, `Hegemon.Consensus.ProvenBatchBinding.accepts_iff_binding_preconditions`, proving the complete executable proven-batch binding predicate for proof route compatibility, tx-count binding, statement-commitment binding, DA-root binding, nonzero DA chunks, block-artifact envelope kind/profile agreement, and recursive-block receipt-root exclusion. `formal/lean/Hegemon/Consensus/GenerateProvenBatchBindingVectors.lean` emits examples checked against the production `evaluate_proven_batch_binding` helper used before block proof verification. Treat this as real but narrow evidence: DA erasure-code soundness, BLAKE3 security, recursive proof cryptographic soundness, native backend soundness, and complete native-node equivalence remain separate review targets.
- `formal/lean/Hegemon/Transaction/PublicInputs.lean` contains real Lean public-input shape theorems for fixed vector widths, boolean flags, inactive-field zeroing, active nullifier/commitment nonzero checks, nonempty transaction admission, canonical balance-slot asset ordering, and stablecoin asset membership. `formal/lean/Hegemon/Transaction/GeneratePublicInputVectors.lean` emits examples checked against production `TransactionPublicInputsP3::validate`. Treat this as real but narrow evidence: it does not prove note commitment hashing, nullifier derivation, ciphertext hash derivation, BLAKE3 statement-hash security, or proof-system soundness.
- `formal/lean/Hegemon/Transaction/PublicInputBinding.lean` contains real Lean public/serialized input binding theorems for merkle-root, fee, signed value-balance, balance-slot asset, stablecoin policy, oracle, and attestation agreement before `TransactionPublicInputsP3` construction. `formal/lean/Hegemon/Transaction/GeneratePublicInputBindingVectors.lean` emits examples checked against production `transaction_public_inputs_p3_from_parts`. Treat this as real but narrow evidence: it does not prove Poseidon2/BLAKE3 equivalence, note commitment hashing, nullifier derivation, ciphertext hash derivation, or proof-system soundness.
- `formal/lean/Hegemon/Transaction/StatementHash.lean` contains real Lean statement-hash preimage theorems for the domain separator, fixed-width digest padding, little-endian scalars, raw stablecoin flag byte, and two's-complement signed balances. `formal/lean/Hegemon/Transaction/GenerateStatementHashVectors.lean` emits exact preimage bytes checked against the shared Rust helper used by transaction receipts and consensus tx-leaf binding. Treat this as real but narrow evidence: it does not prove BLAKE3 collision resistance, BLAKE3 implementation equivalence, note commitment hashing, nullifier derivation, ciphertext hash derivation, or proof-system soundness.
- `formal/lean/Hegemon/Native/TxLeafArtifact.lean` contains real Lean native tx-leaf artifact parser theorems for bounded serialized STARK/public-tx counts, proof-length caps, commitment row/coeff caps, backend-byte defaulting, bad backend rejection, trailing-byte rejection, and truncation rejection. `formal/lean/Hegemon/Native/GenerateTxLeafArtifactVectors.lean` emits artifact bytes checked against production `superneo-hegemon` decoding and canonical re-encoding. Treat this as real but narrow evidence: it does not prove native lattice backend security, STARK proof soundness, receipt-root fold soundness, statement-digest collision resistance, or production cryptographic acceptance.
- `formal/lean/Hegemon/Native/ReceiptRoot.lean` contains real Lean native receipt-root parser and structural schedule theorems for bounded leaf/fold counts, non-empty expected leaf agreement, `fold_count = leaf_count - 1`, exact fold challenge count, exact parent-row dimensions, trailing-byte rejection, and truncation rejection. `formal/lean/Hegemon/Native/GenerateReceiptRootVectors.lean` emits artifact bytes checked against production `superneo-hegemon` decoding, canonical re-encoding, and the structural validator called before backend fold verification. Treat this as real but narrow evidence: it does not prove native lattice backend security, backend transcript challenge derivation, cryptographic fold proof soundness, statement-digest collision resistance, or production cryptographic acceptance.
- The claims ledger is the source of record for formal-security claim status, production eligibility, gates, and residual risks. Documentation may summarize it, but must not promote a claim beyond the ledger status.
- The blueprint DAG is a JSON review map for the claims ledger, not a Lean proof file. It makes dependencies, target review, implementation bindings, falsification cases, and scope boundaries machine-checkable. The gate rejects missing nodes, dangling edges, self-dependencies, dependency cycles, missing implementation or evidence paths, and claim/blueprint drift so stale evidence cannot silently support a production claim.
- Every production-eligible blueprint node must name at least one cheap falsification case, such as an invalid vector, negative unit test, counterexample config, or checker case that would fail quickly if the claim were false. Target-review acceptance means the statement and evidence target have been reviewed for CI gating. It is not external cryptographic acceptance, and it does not change any ledger residual risk.
- A local pass is preflight evidence. Branch acceptance requires the CI `formal-core` job to run `bash scripts/check_formal_core.sh` and report the blueprint-DAG step passed. Passing `formal-core` is release-gate evidence, not a proof of the full Rust implementation and not a replacement for TLC/Apalache runs, external cryptanalysis, or checked-in acceptance artifacts. The native backend remains `candidate_under_review` / `structural_candidate`; blueprint target review must not be described as production-accepted cryptography.
- Formal specs live under `circuits/formal/` and `consensus/spec/formal/`. Run them with either [TLC](https://github.com/tlaplus/tlaplus) or [Apalache](https://apalache.informal.systems/) when a spec changes:
  ```bash
  # Example: verify MASP balance preservation
  cd circuits/formal
  tlc -deadlock transaction_balance.tla -config transaction_balance.cfg

  # Example: check the PoW fork-choice invariant
  cd consensus/spec/formal
  apalache-mc check --max-steps=20 --inv=ForkChoiceInvariant pow_longest_chain.tla
  ```
- If TLC/Apalache are installed locally, `HEGEMON_FORMAL_RUN_MODEL_CHECKERS=1 bash scripts/check_formal_core.sh` also asks the wrapper to run those model-checker commands. The default CI gate checks the model inventory and reference vectors without assuming those external binaries exist.
- Continuous security testing harnesses:
  - `circuits/transaction/tests/security_fuzz.rs` – property-based witness validation (balance slots, nullifiers, input/output bounds).
  - `network/tests/adversarial.rs` – tampered handshake transcripts and miner-share control messages must be rejected deterministically.
  - `wallet/tests/address_fuzz.rs` – randomized address derivations plus adversarial mutations.
  - Root-level `tests/security_pipeline.rs` orchestrates cross-component adversarial flows, including simulated pool payout tampering.
- The proving attack ledger lives in [docs/crypto/proving_attack_matrix.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/proving_attack_matrix.md).
- `HEGEMON_REDTEAM_MODE=ci bash scripts/run_proving_redteam.sh` is the merge-blocking hostile proving suite.
- `HEGEMON_REDTEAM_MODE=full bash scripts/run_proving_redteam.sh` is the heavier release-hardening pass and adds fuzz/adversarial suites that are too expensive for every PR.
- CI job `formal-core` runs `bash scripts/check_formal_core.sh`; release job `security-gates` runs the same gate before publishing binaries.
- CI job `security-adversarial` (see `.github/workflows/ci.yml`) runs the `ci` red-team suite on every push/PR. Failures block merges until triaged via `runbooks/security_testing.md`.
- CI job `dependency-audit` and release job `security-gates` run `./scripts/dependency-audit-gate.sh`; every cargo-audit finding must either be removed or listed in `config/dependency-audit-waivers.json` with expiry, package/version, reason, and tracking id.

## 4. Finding log template

Document each review or audit item under this heading so engineers and auditors see a unified ledger.

```json
{
  "id": "SEC-2025-0001",
  "source": "Cryptanalysis / Lattice",
  "component": "crypto::ml_kem",
  "description": "Side-channel leakage in deterministic keygen seed schedule",
  "severity": "high",
  "status": "patched",
  "evidence": "link to PoC or transcript",
  "remediation": "reference to PR + commit",
  "design_notes": "DESIGN.md §1 updated with new randomness domain separation",
  "tests": ["cargo test -p synthetic-crypto --test kem_regression"]
}
```

Keep the log chronological; when closing a finding, link the merge commit and update the affected documents.

### 2026-04-23 hostile review findings

```json
[
  {
    "id": "SEC-2026-0001",
    "source": "Hostile security review",
    "component": "consensus::PowConsensus",
    "description": "Legacy PoW block validation accepted valid work without binding the block to a registered miner ML-DSA key.",
    "severity": "critical",
    "status": "patched",
    "evidence": "consensus/tests/pow_rules.rs::pow_block_requires_registered_miner_identity and ::pow_block_requires_valid_miner_signature",
    "remediation": "PoW headers now require exactly one ML-DSA signature, no BFT bitmap, and a validator_set_commitment that maps to the registered miner key.",
    "design_notes": "DESIGN.md and METHODS.md document miner identity binding.",
    "tests": ["cargo test -p consensus --test pow_rules -- --nocapture"]
  },
  {
    "id": "SEC-2026-0002",
    "source": "Hostile security review",
    "component": "consensus::PowConsensus / node::native",
    "description": "PoW seal verification tolerated compact difficulty mismatches and checked work against the seal's claimed difficulty.",
    "severity": "high",
    "status": "patched",
    "evidence": "consensus/tests/pow_rules.rs and node/src/native/mod.rs::validate_native_block_meta",
    "remediation": "Native PoW verification requires exact block difficulty bits and checks work against the native target selected for that height.",
    "design_notes": "DESIGN.md and METHODS.md document exact compact-bit binding.",
    "tests": ["cargo test -p consensus pow_rules -- --nocapture", "cargo test -p hegemon-node --lib"]
  },
  {
    "id": "SEC-2026-0003",
    "source": "Hostile security review",
    "component": "node::native",
    "description": "Development node builds could honor HEGEMON_PARALLEL_PROOF_VERIFICATION=0 and diverge from fully verified block validity.",
    "severity": "high",
    "status": "patched",
    "evidence": "node/src/native/mod.rs imports non-empty shielded blocks through consensus proof verification",
    "remediation": "The env var is now a logged no-op; block import and production always keep proof verification enabled.",
    "design_notes": "METHODS.md documents proof verification as non-optional.",
    "tests": ["cargo test -p hegemon-node --lib"]
  },
  {
    "id": "SEC-2026-0004",
    "source": "Hostile security review",
    "component": "network::PeerIdentity legacy handshake",
    "description": "Repeated legacy handshakes between the same static identities derived deterministic KEM seeds and nonces, risking AEAD key/nonce reuse on reconnect.",
    "severity": "high",
    "status": "patched",
    "evidence": "network/tests/adversarial.rs::repeated_legacy_handshakes_rekey_the_first_channel_nonce",
    "remediation": "Offer, acceptance, and confirmation paths now use OS-random transcript nonces and KEM encapsulation seeds.",
    "design_notes": "DESIGN.md and METHODS.md document per-session rekeying.",
    "tests": ["cargo test -p network --test handshake --test adversarial -- --nocapture"]
  },
  {
    "id": "SEC-2026-0005",
    "source": "Hostile security review",
    "component": "pq-noise::PqHandshake",
    "description": "ML-KEM encapsulation seeds were derived from public transcript hashes, letting a passive observer reproduce encapsulation randomness.",
    "severity": "critical",
    "status": "patched",
    "evidence": "pq-noise/src/handshake.rs::handshake_does_not_use_public_transcript_as_kem_seed",
    "remediation": "Encapsulation seeds now come from OsRng; transcript bytes remain public context for signatures and key derivation only.",
    "design_notes": "DESIGN.md and METHODS.md document secret OS randomness for protocol KEM callers.",
    "tests": ["cargo test -p pq-noise"]
  },
  {
    "id": "SEC-2026-0006",
    "source": "Hostile security review",
    "component": "network::SecureChannel",
    "description": "The legacy secure channel reused one AES-GCM key for both directions with both counters starting at zero.",
    "severity": "critical",
    "status": "patched",
    "evidence": "network/tests/adversarial.rs::legacy_channel_uses_directional_keys_for_first_nonce",
    "remediation": "Session material now derives initiator-to-responder and responder-to-initiator AEAD keys with separate domain labels.",
    "design_notes": "DESIGN.md documents directional keys and bounded network codec.",
    "tests": ["cargo test -p network --test adversarial -- --nocapture"]
  },
  {
    "id": "SEC-2026-0007",
    "source": "Dependency audit",
    "component": "workspace dependencies",
    "description": "cargo audit is now a merge/release gate; remaining advisories require explicit expiring waivers.",
    "severity": "high",
    "status": "mitigated",
    "evidence": "scripts/dependency-audit-gate.sh and config/dependency-audit-waivers.json",
    "remediation": "CI and release workflows run the gate. ML-KEM/ML-DSA were upgraded off pre/RC paths; network and PQ Noise trust-boundary frames moved from bincode to bounded postcard codecs.",
    "design_notes": "docs/DEPENDENCY_AUDITS.md records the gate and waiver policy.",
    "tests": ["./scripts/dependency-audit-gate.sh"]
  }
]
```

## 5. Local checklist

1. Read `DESIGN.md`, `METHODS.md`, and this file before any cryptographic, miner-identity, or network change.
2. Run `bash scripts/check_formal_core.sh` before opening security-sensitive PRs.
3. If modifying circuits or hashes, update `circuits/formal/README.md` and rerun TLC/Apalache when available; paste the summary output into the PR description.
4. If touching consensus logic, rerun `consensus/spec/formal` checks plus the network adversarial test with PoW-specific seeds.
5. Before tagging a release, run `./runbooks/security_testing.md` steps to collect fresh artifacts for miners, pool maintainers, and auditors.
