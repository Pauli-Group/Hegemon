# Daybreak relation and semantic regeneration map

Date: 2026-09-07
Scope: defensive integration map for the proposed `bind_sponge` tail-padding repair and the
typed stable-asset membership strengthening. This is not a regeneration receipt, merge approval,
security proof, proof-generation authorization, or production-authority decision.

## Outcome

Treat the two repairs as different change classes.

1. Splitting `bind_sponge`'s `Some(None)` case from its out-of-range `None` case changes the
   source-owned executable relation. The added final-block chaining/zero equations change the
   serialized HGV8RP03 program bytes, its 64-byte SHA-512, its 48-byte relation id, every proof
   statement bound to that id, and every exact generated theorem or artifact derived from the old
   program. Old SMZ9 proofs do not become proofs for the repaired relation.
2. Adding the enabled stable asset to the typed target's public `balanceAssets` membership
   requirement is semantic-only if the existing executable root 1042 remains unchanged. It repairs
   typed-to-packed completeness by making the typed predicate match the already stronger packed
   relation. It changes semantic-source digests, semantic adequacy vectors and descendant Lean
   claims, but not relation bytes, relation id, SMZ9 wire bytes, proof geometry, or existing proof
   verification. If root 1042 or its encoder is altered instead, it becomes another relation-byte
   change and must follow the full relation path below.

The safe integration boundary is therefore: land and review the typed rule independently, then
regenerate the executable relation from the padding repair, and only after that rebuild every
identity descendant. Never refresh a digest merely to make a stale check green.

## Source roots and identity chain

The relation source of truth is the symbolic compiler in
`circuits/transaction/src/smallwood_poseidon2_v8_semantics.rs`. `bind_sponge` feeds all note,
nullifier, action-intent and authorization sponge families into the expression/CSR encoders in
`circuits/transaction/src/smallwood_poseidon2_v8_program.rs`. The current checked-in source product
is `testdata/formal_core_vectors/poseidon2_v8_relation_program.bin`; the adjacent
`poseidon2_v8_relation_program_transcript.json` is the Lean/Rust transcript conformance vector.

The identity is derived, not chosen:

```text
symbolic compiler
  -> encode_smallwood_poseidon2_v8_program()
  -> relation-program.bin
  -> SHA-512(program bytes)
  -> first 48 bytes = native relation id
```

The current constants are duplicated intentionally across these fail-closed surfaces and all must
move together after review of the new bytes:

- `SMALLWOOD_POSEIDON2_V8_PROGRAM_TRANSCRIPT_BYTES`,
  `SMALLWOOD_POSEIDON2_V8_PROGRAM_SHA512`, and
  `SMALLWOOD_POSEIDON2_V8_PROGRAM_DIGEST` in
  `circuits/transaction/src/smallwood_poseidon2_v8_program.rs`;
- `canonicalProgramTranscriptBytes`, `canonicalProgramSha512Hex`, `canonicalProgramSha512`, and
  `canonicalNativeRelationIdHex` in
  `formal/lean/Hegemon/Transaction/Poseidon2V8RelationProgram.lean`;
- `EXPECTED_BYTES`, `EXPECTED_SHA512`, and any changed geometry/count words in
  `scripts/generate_poseidon2_v8_relation_program_components_lean.py`;
- the compiled relation block in `config/smallwood-v8-poseidon2-relation-manifest.json`, the
  relation-manifest hash and claim text in `config/smallwood-v8-poseidon2-profile-manifest.json`,
  and the diagnostic JSON reports that embed the program identity;
- `SMALLWOOD_POSEIDON2_V8_ARTIFACT_RELATION_DIGEST` in
  `protocol/shielded-pool/src/poseidon2_pending_action_artifact.rs`.

The magic `HGV8RP03`, SMZ9 profile id 6, V8/Eta/family-1/action-10/backend-2/domain-set-4 tuple,
and 120-word public statement are not themselves evidence of byte compatibility. They may remain
the same only because the 48-byte relation id is the actual per-program discriminator. Any release
or review text that quotes the old byte count or digest is stale even if the magic is unchanged.

## Generated relation products

After the canonical binary is installed, regenerate from that binary, not from a hand-copied
table:

- `SmallWoodV8Smz9RelationProgramComponentsGenerated.lean` contains the complete parsed program;
- 41 `SmallWoodV8Smz9ProgramCanonicalityCsr00..40.lean` shards, six
  `SmallWoodV8Smz9ProgramCanonicalityDescriptors00..05.lean` shards, and
  `SmallWoodV8Smz9ProgramCanonicalityGenerated.lean` are the 48 canonicality certificate modules.

The shard counts are outputs, not invariants. If the added CSR attempts cross a 512-attempt shard
boundary, the generator may create a new shard; remove an obsolete generated shard only after the
new generated inventory has been reviewed and its import graph updated. Do not manually preserve
"48 files" as an acceptance condition.

The following checked data also embed the old identity or program shape and must be regenerated or
deliberately re-reviewed: `poseidon2_v8_hash_kernel_refinement.json`,
`poseidon2_v8_semantic_adequacy.json`, the relation transcript JSON,
`smallwood_poseidon2_v8_smz9_source_security_report.json`, and
`smallwood_poseidon2_v8_smz9_executable_zk_refinement.json`. A changed number of retained linear
constraints can change gamma count, proof-size projection and parser/headroom calculations even
when the 686-row, 368-column packed witness geometry stays fixed. Recompute; do not assume the
122,863-byte projection survives.

## Formal descendants invalidated by the relation-byte repair

Every theorem whose subject is the exact generated expression list, roots, CSR attempts, program
digest, or current-source acceptance must be rechecked and, where indices changed, reproved. The
directly exposed families include:

- all generated component and canonicality modules;
- `SmallWoodV8Smz9ProgramPolynomials`, `CurrentPublicContext`, `CurrentProgramPiop`,
  `CurrentProgramOpeningBinding`, `CurrentSourceAcceptance`, `DecodedPolynomialSource`,
  `ConcreteOracleExtraction`, and the current privacy-game/composition modules that quantify over
  the generated program;
- `SemanticBinding`, `SemanticDenseRange`, `SemanticDecoder`, `SemanticInactiveWitness`,
  `SemanticCanonicalWitness`, `SemanticAssetMembership`, `SemanticInterpolation`,
  `SemanticBalance`, `SemanticAuthorization`, `SemanticAuthorizationNonSingle`,
  `SemanticStablecoin`, `SemanticStablecoinEnabled`, and
  `SemanticCompletenessCounterexample`;
- `HashDependencyCertificate`, `HashRootCertificate`, `SemanticCryptographicLinks`,
  `SemanticPoseidonKernelBinding`, and the local/full Poseidon2 template refinements.

The padding counterexample theorem/report becomes historical negative evidence after the new
relation rejects it. It must not remain phrased as a counterexample to the current program.
Generic Goldilocks algebra, Poseidon2 permutation theorems, SMZ9 parser lemmas, QROM machinery and
geometry-only results are not automatically invalidated, but every specialization theorem that
names HGV8RP03 or the generated program must be rebound. Passing compilation from an unchanged
generic import is not evidence that the exact specialization survived.

The typed stable-membership edit separately invalidates
`Poseidon2V8SemanticSpecification.lean`, `Poseidon2V8SemanticAdequacy.lean`, its generated semantic
vector, all semantic endpoint theorems that unfold `ExactV8RelationSemanticValid`, and the formal
source-tree/claim digests. The existing root-1042 completeness counterexample should be converted
into a positive regression: the old statement is rejected by the strengthened typed predicate,
while a statement listing asset 1001 remains eligible for packed construction. This semantic-only
edit does not require relation-program regeneration.

## Proof, carrier, selector, and artifact compatibility

The repaired relation id is carried in the HGV8TX02 native leaf and is checked by the frontend,
the native contextual decoder, the source-owned relation factory, the offline PendingAction codec,
the artifact tool, and the candidate verifier input. Consequently:

- old proof bytes plus the old relation id are not accepted as the repaired current relation;
- relabeling old proof bytes with the new id fails transcript/relation verification;
- sidecars, caches, receipts, aggregates, manifests, or an honest-lowering check cannot translate
  an old proof into a new proof;
- retained primary/independent proof bundles, complete PendingActions, chain report, source
  inventories and `retained-artifact-manifest.json` remain immutable historical evidence and must
  not be edited in place or credited to the new relation;
- any future retained campaign needs freshly generated independent proofs, fresh source inventory,
  new exact carrier bytes, mutation checks, lifecycle same-byte evidence, restart/reorg/fresh-node
  evidence, and independent review.

The carrier grammar and selector tuple may remain structurally unchanged, but their accepted
context changes because it contains the relation digest. Re-run the wallet/RPC, relay, mempool,
mining, block import, sync, restart, reorg and fresh-node exact-byte tests only when proof generation
and node execution are separately authorized. The active production capability remains `None` in
`protocol/versioning/src/lib.rs`; `Poseidon2V8ProductionBinding::from_source_at` and
`require_source_at` remain fail closed. This regeneration must not add a registry entry, select a
successor, change an activation height, or enable actions 10/11.

## Safe regeneration order and commands

The commands below are the future authorized integration sequence. They were not run for this map.
Use a clean, dedicated integration worktree or first freeze the current dirty-tree inputs; never
overwrite retained artifacts.

1. Apply the two source edits and their focused negative/positive tests. Keep the stable-membership
   semantic change separate in review from the padding relation change.

2. Bootstrap the new relation identity from the encoder. The old KAT is expected to fail and print
   the newly encoded byte count, SHA-512 and relation id:

   ```sh
   cargo test -p transaction-circuit \
     smallwood_poseidon2_v8_program::tests::program_digest_known_answer_and_descriptor_mutation \
     -- --nocapture
   ```

   Review the emitted count/digest and the descriptor/count delta. Then update only the Rust KAT
   constants and any count/size constants justified by that output. Re-run the same test and the
   focused padding tests until they pass.

3. Build the source-owned artifact emitter and publish to a new temporary path. The emitter uses
   exclusive creation and refuses to overwrite a different existing program:

   ```sh
   cargo build --locked --profile retained-proof -p transaction-circuit \
     --example smallwood_poseidon2_v8_artifact
   tmpdir="$(mktemp -d /private/tmp/hgv8rp03-regenerate.XXXXXX)"
   target/retained-proof/examples/smallwood_poseidon2_v8_artifact \
     program "$tmpdir/poseidon2_v8_relation_program.bin"
   shasum -a 512 "$tmpdir/poseidon2_v8_relation_program.bin"
   ```

   Independently parse/review the temporary binary and confirm the reported SHA-512 prefix. Only
   then replace `testdata/formal_core_vectors/poseidon2_v8_relation_program.bin` as one reviewed
   atomic integration change. Preserve the old binary by commit history, not by modifying retained
   proof directories.

4. Update the Lean relation KAT constants from the reviewed bytes and regenerate the transcript
   vector to a temporary file before replacement:

   ```sh
   cd formal/lean
   lake build Hegemon.Transaction.GeneratePoseidon2V8RelationProgramVectors
   lake exe gen_poseidon2_v8_relation_program_vectors > \
     "$tmpdir/poseidon2_v8_relation_program_transcript.json"
   cd ../..
   python3 -m json.tool "$tmpdir/poseidon2_v8_relation_program_transcript.json" >/dev/null
   ```

   Exact-compare its identity and geometry with the Rust emitter, then install the reviewed JSON.

5. Update the Python generator's expected byte count, SHA-512 and changed geometry words. Generate
   the complete component module to temporary output, review it, then generate the canonicality
   shards:

   ```sh
   python3 scripts/generate_poseidon2_v8_relation_program_components_lean.py \
     --self-test testdata/formal_core_vectors/poseidon2_v8_relation_program.bin
   python3 scripts/generate_poseidon2_v8_relation_program_components_lean.py \
     testdata/formal_core_vectors/poseidon2_v8_relation_program.bin > \
     "$tmpdir/SmallWoodV8Smz9RelationProgramComponentsGenerated.lean"
   python3 scripts/generate_poseidon2_v8_program_canonicality_lean.py \
     --input testdata/formal_core_vectors/poseidon2_v8_relation_program.bin \
     --output "$tmpdir/SmallWoodV8Smz9ProgramCanonicalityGenerated.lean"
   ```

   The canonicality generator writes sibling shards beside its output. Review the complete
   temporary inventory, then replace the generated files together. Afterwards run the repository
   checker in check mode:

   ```sh
   bash scripts/check_poseidon2_v8_relation_program_components_lean.sh
   ```

6. Regenerate the semantic adequacy and hash-kernel vectors from their Lean generators, then run
   the focused Rust exact-comparison tests named in
   `config/smallwood-v8-poseidon2-relation-manifest.json`. Recompute the source-security,
   executable-ZK and proof-size reports through their existing source-owned emitters. If the
   projected proof or carrier size changes, update the profile manifest, transport caps only when
   separately authorized, and all size assertions from one coherent report. A cap increase is a
   protocol decision, not a digest-refresh detail.

7. Reprove/recheck the exact formal descendants above. Integrate their imports in
   `formal/crypto/HegemonCrypto.lean` and credited roots only after each theorem has been reviewed
   against the new generated indices. Then run the established gates:

   ```sh
   bash scripts/check_formal_crypto.sh
   bash scripts/check_formal_core.sh
   python3 -B scripts/smz9_joint_acceptance_probe.py --self-test
   python3 -B scripts/smz9_hidden_leaf_qrom_screen.py --self-test
   git diff --check
   ```

   These gates are regression evidence, not a semantic-adequacy or PQ128 certificate.

8. Refresh governance only after theorem content is final. Obtain blueprint review digests and
   policy-input digests from the checker, update `content_blake3`, `formal_source_tree_blake3`, and
   `policy_inputs_blake3` with the exact reviewed outputs, then rerun the checks:

   ```sh
   cargo run --quiet --manifest-path scripts/hegemon_formal_core/Cargo.toml -- \
     print-blueprint-review-digests config/formal-security-blueprint.json
   cargo run --quiet --manifest-path scripts/hegemon_formal_core/Cargo.toml -- \
     print-governance-policy-inputs-digest config/formal-security-claims.json
   cargo run --quiet --manifest-path scripts/hegemon_formal_core/Cargo.toml -- \
     print-governance-policy-inputs-digest config/formal-security-blueprint.json
   cargo run --quiet --manifest-path scripts/hegemon_formal_core/Cargo.toml -- \
     print-governance-policy-inputs-digest config/active-goal-progress.json
   cargo run --quiet --manifest-path scripts/hegemon_formal_core/Cargo.toml -- \
     check-active-goal-progress config/active-goal-progress.json
   cargo run --quiet --manifest-path scripts/hegemon_formal_core/Cargo.toml -- \
     check-blueprint config/formal-security-blueprint.json \
     --claims config/formal-security-claims.json
   cargo test --quiet --manifest-path scripts/hegemon_formal_core/Cargo.toml governance_
   ```

   `check-active-goal-progress` reports the expected current formal-source digest when stale; use
   that source-derived value only after inspecting the included source set. Do not change review
   decisions, completion percentages, status, or authority merely to refresh hashes.

9. Only under separate proof-generation and lifecycle authorization, create a new retained
   directory and produce two independently randomized proofs and complete PendingActions. Verify
   them with independently built exact binaries and carry the same proof bytes through the full
   product lifecycle. Never mutate the old `hgv8rp03-84002dce5de2e03a` bundles or manifest.

## Risk assessment boundary

No immutable final patch was supplied, so this document cannot satisfy the patch-risk skill's
exact-patch identity requirement and does not issue a merge recommendation or auto-merge label.
For the prospective padding repair, impact-if-wrong is **critical** because it changes the
consensus proof relation and can otherwise preserve a verifier over-acceptance gap; regression
likelihood is **high** until regenerated identity, proof-size, formal-specialization and lifecycle
checks pass; regression protection is currently **partial**; recoverability is **hard** after any
activation because old and new proof bytes are cross-version incompatible; confidence in this
dependency map is **moderate** because no regeneration or exact final diff was executed.

Strongest padding counterexample: a proof verifier accepts an assignment with an unconstrained
final tail lane because it never runs the full-witness canonical re-lowering guard. Legitimate
control: encode out-of-range lanes as zero on block zero or the previous final lane on later
blocks, bind the new relation id at every verifier/carrier boundary, and retain the existing
fail-closed `None` production capability until the complete security and lifecycle contract passes.

Strongest stable-membership counterexample: the old typed target accepts an enabled stable burn
whose stable asset is absent from all four public balance slots, while executable root 1042 rejects
every packed witness. Legitimate control: require enabled stable-asset membership in the typed
public balance list and add both rejection and positive listed-asset regressions without changing
root 1042.

Status-quo risk is known: leaving padding unchanged preserves a raw-relation over-acceptance gap;
leaving typed membership unchanged preserves a semantic-to-packed completeness contradiction.
Production is nevertheless currently fail closed because no V8 capability or successor selection
is active.
