# Controlled issued assets: Development V3

This finite Development integration adds ordinary and bounded-policy issued-asset
proofs, authenticated registry accounting, mandatory current credentials, freezing
and proof-authorized controls updates in the native shared pool. Native HGN keeps
its existing monetary rules. Issuer seizure and automatic recovery are unavailable;
a second policy branch still requires the note opening and policy material.
Production authority is not enabled.

## Moving-chain Development revision and acceptance scope

The revised path preserves the proof's canonical reference parent H, hash and
block-end note root while accepting an actual inclusion parent P with
`H <= P <= H+12`. Eligible inclusion blocks are H+1 through H+13. The spend
relation now has a fresh v3 source identity and still exposes 134 public words.
Every active private credential expiry E and `E-(H+12)` is constrained to 48 bits;
host validation rejects overflow or an H+12 outside that range. This covers P
under the existing parent-height expiry convention, not necessarily inclusion
P+1. A bounded-policy branch still requires `not_before <= H`; a later P cannot
unlock a branch early.

The reference's separately authenticated issued-asset registry root must equal
the complete current registry root at P. The current row and all mandatory
credential/freeze/mint checks remain enforced on every branch. Freeze, revocation
or any other registry-root change immediately stales an older proof, including a
change to another asset. Accounting uses current counters and current issuer,
epoch, oracle, attestation and collateral rules at P. Nullifiers are checked
against the shared current V8 pool and the block's staged inputs. All three
outputs and native fees remain in that same pool.

Administrator proofs retain their relation and bind the exact current prepared
before/after rows and roots, preserving issuer configuration, policy version and
counters. Their public expiry must cover P; reference age cannot extend it.
Consumed administrator action identities remain durable and replay-protected.
Canonical receipts bind both the historical reference and actual inclusion
parent. A tip change or reorg revalidates reference age/canonicality, current
controls, expiry and nullifiers against restored canonical state.

The atomic `hegemon_assetSnapshot [asset_id|null, reference_hash|null]` readback
returns reference `parameters` and `registry` with a separate `current_context`;
parameters advertise `source.reference_window=12`. A historical reference is
returned only while its complete registry root is current. The fresh manifest
policy changes the network/genesis identity; regenerate manifests and affected
spend proofs for this source. Development source authority and its finite actual
inclusion interval remain mandatory. Production authority is not enabled.

The actual V10 moving-chain lifecycle passed with 13 genuine proof candidates
(8 asset, 4 administrator and 1 native), 21 unique checks and 22 observations.
All 11 owned processes were reaped and the serialized guard exited zero.
The retained native receipt is SHA256
`476dfcdf4960cfd838600b2d5ef0218b0eea4f0c39fc7a3d4103a94aedbacbc0`.
The [final handoff](../.agent/stablecoin-moving-chain-v1/FINAL_HANDOFF.md) binds the
source package and separate conditional security disposition; lifecycle success
does not supply a cryptographic security assumption.

The five admitted asset geometries (ordinary depths 4/8/16 and bounded depths 4/8)
retain `D <= 14088`; bounded depth 16 remains excluded by the unchanged native cap.
Fresh moving-chain lifecycle scope is ordinary depth 4 and bounded depth 4 only. The V10 run passed 13 genuine candidates: 8 asset, 4 administrator and 1 native.
Its 21 unique checks and 22 observations include both strict retained two-node
body readbacks. This is not the historical 23-gate run. The focused summary
retains 101 passing executions, not distinct tests, and 3 ignored. The separate
aggregate-reorg regression passed three gates with zero proofs; nine retry
fixtures are bounded helper checks. Earlier failed runs remain literal history.


The three source-bound conditional arguments are: (1) current CSR/public134
binding and geometry under accepted-source/decoder interpretation; (2) issuer,
credential and administrator authority on the same recovered packet and physical
execution, with the normalized chosen-context seven-game bound; and (3) the actual
witness-free V10 operational public simulator for source bytes/errors and the same
persistent physical oracle lifetime. Witness indistinguishability is not a
substitute for the third endpoint. These arguments retain PR205, exact source and
compiler/serialization/platform interpretation, fresh RNG/field coins, F1 recovery
and efficient extraction, authenticated provider provenance, primitive and
chosen-context game hypotheses, the same physical shared QRO, query/lifetime
bounds and `ExternalAdaptiveReprogramming`. They grant no unconditional backend
security or production authority. The final conditional disposition and review
are recorded separately in
`.agent/stablecoin-moving-chain-v1/changed-arguments/final-security-staging-v6/final-security-v1.json`;
that receipt must be verified before the integration handoff is finalized.

The earlier certificates, source IDs, measurements and acceptance chronology below
are explicitly historical exact-parent evidence. They do not certify v3 by reuse.
The SMZE backend and cryptographic parameters are unchanged. No unconditional
whole-backend or production security claim follows.

## Implemented contract

`circuits/transaction/src/asset_spend_v1.rs` defines a fixed two-input/three-output relation. The first input is the non-native asset note, absent only for mint. The second input funds the HGN fee. Outputs are the asset payment, asset change and native fee change. Separate bounded equations enforce asset conservation and native fees. Mint proves knowledge of the configured V8 issuer secret; burn requires the committed ordinary or bounded-policy holder authorization. Asset IDs are nonzero 32-bit values.

Every asset input and both asset outputs, including change and zero-valued outputs, require membership in the current credential tree. A leaf binds asset, policy version, receiving key, full ordinary authority digest or committed bounded-policy owner, and expiry. The proof binds the current chain, reference parent, note root, registry root, credential root and exact transaction statement. Removing a leaf from the current tree revokes that credential. The current model requires a provider to issue credentials for the actual keys; the protocol does not establish a real-world identity from an address or infer screening facts.

`circuits/transaction-core/src/asset_registry_v1.rs` authenticates up to sixteen rows in fresh hash domains. It reuses the V8 configuration digest, issuer commitment, supply counters, epoch cap, oracle freshness, attestation and collateral accounting. Asset IDs sharing the low four bits cannot both occupy this candidate registry. Its prepared accounting helpers are deliberately not proof verifiers. The proof-aware candidate ledger must authenticate the complete current row and verify the proof before applying them.

Freezing and mint disablement are separate controls. A freeze blocks transfer, mint and burn of the issued asset. Disabling mint or retiring issuance leaves eligible existing-note transfers and burns available. `asset_policy_admin_v1` proves knowledge of the asset's separate policy-admin secret for an exact controls update. Such updates preserve the complete issuer configuration, policy version and supply counters while changing credential root/depth, freeze and mint flags. Registry-root freshness prevents stale controls. Consumed canonical admin statement identities must also be retained so a freeze/unfreeze cycle cannot replay an old randomized proof.

The historical candidate wire retains its own identity. Native Development uses distinct exact `HGANSP01` spend and `HGANAD01` administrator carriers under a typed authority constructed from the fresh manifest and exact compiled sources. Accepted profiles are ordinary depths 4/8/16 and bounded depths 4/8, with the unchanged 2 MiB inner cap and one asset action per block. Unsupported bounded depth 16 rejects before proving/admission. The native adapter verifies proofs and current policy/accounting, then publishes registry/admin-history snapshots in the existing V8 block transaction. Notes, positions and spent nullifiers use the same global native pool, including all three outputs. Startup and reorg replay use the manifest-derived zero-supply genesis and exact accepted bodies. These paths have built successfully. The V10 finite moving-chain lifecycle passed as recorded above; the earlier per-run receipts under `.agent/stablecoin-v1-20261016/` remain historical exact-parent evidence.

`wallet/src/asset_spend_v1.rs` supplies ordinary and bounded-policy asset-note codecs, three-output encryption/decryption and a prepared proof API. Its ASN1 ordinary plaintext is exactly 1,024 bytes; each output ciphertext is 2,608 bytes using ML-KEM-1024 and ChaCha20-Poly1305 in fresh asset domains. Schema 19 adds persistent discovery, selection, reservations, exact-byte submission journaling and canonical recovery; frozen schema 18 remains read-only with recovery into a fresh store. Asset-route HGN change also enters the existing ordinary private-note view at its original commitment, position and nullifier. The two balance views overlap and must not be summed. `walletd --asset-help` documents public setup, credential witnesses, authenticated controls, sync, construction and submission; build it with `--features development-assets` for the finite Development path. The exact end-to-end wallet acceptance status is recorded with the native lifecycle receipt; source integration alone does not establish it.

Exported wallet attempts retain their input reservations when a reorg removes their inclusion. After syncing the winning chain, explicitly call `asset.abandon` for a stale attempt before reusing its inputs. Abandonment preserves the exact exported bytes and journal identity; its tombstone reserves again if a later rollback returns within its H+12 admission horizon. A rollback can revive an old hold over a newer retained native/private attempt: preserve both immutable bodies and the reservation union, then reject conflicting new export/submission transitions. Check aggregate reservation state before constructing a replacement; timeouts and tip changes alone cannot release exported inputs.

## Shared spending policies

The verified parent scripting baseline is integrated. Asset policies use the same circuit evaluator as native bounded policies: up to two alternatives, each requiring a credential key AND an absolute reference-parent height AND an optional SHA256 preimage. The descriptor commits whether a hashlock claim must publish the complete 256-bit preimage. A releasing claim cannot suppress or change that disclosure. The descriptor and shared nullifier key determine the complete owner digest. Choosing another branch cannot create a second spend identity.

Public mode zero selects the ordinary-only graph and rejects policy data. Mode one selects combined policy geometry. Script input and output creation use asset slot zero/payment slot zero; asset change and native fee change remain ordinary. Mandatory asset conservation, current credentials, expiry and freezing wrap every alternative. They never sit inside a branch that another authorization can skip. A policy owner's current credential is bound to that complete owner, separately from the branch authority key.

The statement has 134 public words. `HGASLC02` is the fresh candidate action, with exactly 9,026 non-proof bytes (130 header, 1,072 public binding, 7,824 ciphertext). Old `HGASLC01` candidates are rejected. The administrative proof has its own v2 relation/context identity and 134-word schema with canonical zero padding; its per-asset administrator key commitment stays in its original domain. No issuer powers are added to native HGN.

## Privacy and security boundary

This candidate discloses the asset ID, policy version, current policy/credential roots, operation, issuance magnitude, credential depth and ordinary/combined graph mode. Required hashlock preimages are deliberately public on releasing claims. Note amounts, participant keys, note openings, credential paths and issuer secrets are witnesses. This differs from the ordinary native public schema and needs explicit review before activation. Credential providers may know the keys they credential. No new privacy claim follows merely from putting their membership checks inside a ZK relation.

SMZE is a fresh SmallWood transcript/wire identity with the existing security parameter target: packing 64, degree two, rho five, six openings, beta two, evaluation domain 2^23, 58 DECS queries, eta five and no grinding. Native SMZD's fixed frame cannot be reinterpreted as this changed relation. A change to the shared engine changes the native source digest even when its native behavior remains unchanged; historical carriers retain their historical namespace.

## Additional formal work (historical exact-parent source)

This section preserves the earlier qualification chronology. Its open/completed
claims are scoped to those artifacts and their final frozen acceptance receipts,
not to the moving-chain revision above.

`formal/lean/Hegemon/Transaction/QualifiedAssetBalanceV1.lean` contains 58 checked semantic theorems (47 retained plus 11 new composition theorems), importing the parent model's 17 theorems. All 75 axiom checks passed with only `propext` and `Quot.sound`. These are bounded model results. The accepted-proof lift explicitly assumes proof soundness and binding of authenticated registry and credential roots. These assumptions are not established by compiling that model.

Native integration adds24 focused arithmetic/source-coordinate theorems and45 source-readout/framing/slot theorems; all compile and audit with only `propext` and `Quot.sound`. A separate development-only `asset_security_readout_v1` tool reconstructed the actual accepted verifier trace for the retained administrator proof and all six asset geometries. An independent audit checked all134 public words, four raw SHA512 commitment frames per proof, every logged field-XOF counter/output, geometry-specific FPP offsets and matrix dimensions. All84 entries in the asset/admin/native relation manifests remain unchanged. The exact execution and independent audit are pinned by `.agent/stablecoin-v1-20261016/native-security/actual-readout-qualification.json`.

The subsequent `asset_raw_ledger_v1` tool used the frozen engine's empty-program recorder to capture the complete ordered classical SMZE verifier oracle closure. Its seven executions include all1,397 singleton calls omitted by the earlier field-only traces. Independent Python replay regenerated7,716,403 raw queries, every canonical field output and singleton answer, all Merkle path propagations, and every rolling ledger digest. The factored export reproduces2,033,840,394 bytes of framed keys and answers without deduplicating repeated calls. `.agent/stablecoin-v1-20261016/native-security/actual-raw-ledger-qualification.json` pins those results. This closes the classical logging omission for these exact verifier executions. It does not supply the original adversary's basis readout, recovered source assignment or expanded primitive output locators, changed-role event coverage, lifetime/sampler composition, efficient extractor or privacy theorem. Those remain required security work; source framing and successful verification do not discharge them.

The development-only `asset_admin_topology_readout_v1` exporter locates the seven administrator commitment output equalities and all134 public-binding rows in the actual adapter CSR. It checks the original generic compressor's operations against actual linear rows and copied product locations; three focused tests pass, including altered-row rejection. The actual export from an included native administrator carrier has6,319 canonical wires and11,460 linear rows. Independent Python replay checks all 2,461 operations,32 symbolic states,134 public bindings and7 output equalities; eight corruptions reject. Its receipt is `.agent/stablecoin-v1-20261016/native-security/actual-admin-topology-qualification.json`. A later bounded Lean artifact checks the complete literal original CSR buffers:180 shards,22,835 entries,11,461 absolute offsets and11,460 targets. All49 closure objects pass kernel replay, five actual-body audits and four standard-axiom summaries. For arbitrary `z`, the transport assumes only `RawSatisfied` of this literal original CSR and derives its row equations, including one selected public-word consequence. A successor then binds all134 actual public coordinates and all7 computed/admin-role output equalities using only that original CSR premise;3 new objects pass replay and8 final roots pass actual-body and standard-axiom audits. This is one exported statement, with no generic public-target-family claim. Issuer/config/counters are committed by the seven-word before/after policy leaves rather than exposed as separate ADMIN coordinates; no leaf-preimage or host-policy fact follows from these equalities. Export-to-literal conformance is independently checked in Python; Rust exporter/compiler refinement and accepted-branch assignment extraction remain outside those theorems. The earlier selected32 row consequences and one operation also pass kernel replay and unchanged native actual-body auditing. All-operation/product/hash composition and `CompressChecked` remain open; these finite results do not establish the full source or cryptographic certificate. This tool adds no proof-acceptance, source-extraction or primitive-security premise.

The additional release obligations below concern the changed roles and semantics under the retained trusted compiler and primitive assumptions. They do not require a new whole-program Rust-equivalence campaign:

1. Bind the actual new source graph and all public/private roles to the integer semantics. In particular, prove the bounded field equations lift without wraparound, input/output asset assignments are exact, issuer knowledge implies authorized issuance and real nullifiers retain their note identity.
2. Establish mandatory credential/freeze semantics for every accepted spending-policy alternative in the integrated ordinary and bounded-policy geometries. Prove asset, participant, intent, current root and expiry binding, including change and all alternate branches. Unsupported branches must remain absent from admission.
3. Bind public accounting to the actual registry state transition: mint cap, epoch rollover, debt, collateral, oracle/attestation freshness and full before/after state. Prepared plans alone are not authority.
4. Bind administrator knowledge and exact update intent to current state and preserved issuer roles/supply. Preserve consumed canonical action identities across restart, snapshot and reorg, with atomic publication alongside the root.
5. Compose the changed relation, public heads, openings, aborts and query ledger with the retained PR205/current-successor security argument under the same disclosed primitive and trusted Rust/compiler interpretation assumptions. Recalculate geometry-dependent bounds; do not relabel old relation evidence as new. Efficient extraction remains an inherited open boundary.
6. Qualify the public-proof privacy game for this disclosed metadata and current credential system, including issuer/admin proofs and their shared oracle history. No new QROM, full-ZK or production authority follows from semantic model theorems or finite mutation tests.
7. Qualify complete native admission and durable lifecycle behavior with fresh source/network identities, wallet persistence/RPC integration, restart/reorg tests and the actual launch gates. A local candidate ledger is not a production state writer.

Recovery would add explicit per-asset opt-in authority, recoverable note information and ordinary/recovery mutual exclusion under one nullifier or deactivation identity. Issuer-driven recovery is intentionally not enabled here. A holder-chosen second credential branch is available within the bounded policy once its authorized spender has the opening and shared policy material. Automatic recovery discovery, decryption/key distribution and provider-assisted issuer recovery remain separate designs; neither is inferred from a second branch. All branches consume the same note nullifier and stay subject to current asset rules.

## Measured candidate qualification (historical exact-parent source)

These are actual generated and independently verified proofs on the same Apple arm64 host (eight logical CPUs), with two Rayon threads and one coordinator proof process at a time. Each cell is one trial, not a statistical performance bound. Prove/verify timers include adapter construction; RSS covers the whole runner, including fixture construction, encryption, graph construction, proving, verification and ledger application. The coordinator ran no concurrent Cargo build or proof. Host-wide interference was not controlled. Each scaling fixture has one active credential leaf, so depth scaling does not establish provider throughput or a populated registry benchmark.

| Asset profile | Credential depth | Proof bytes | HGASLC02 action bytes | Prove s | Verify s | Whole-process RSS GiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| ordinary | 4 | 818,469 | 827,495 | 55.500 | 0.397 | 1.910 |
| ordinary | 8 | 886,973 | 895,999 | 57.223 | 0.436 | 2.213 |
| ordinary | 16 | 1,025,477 | 1,034,503 | 59.476 | 0.503 | 2.400 |
| bounded | 4 | 1,981,061 | 1,990,087 | 93.751 | 1.032 | 2.279 |
| bounded | 8 | 2,049,741 | 2,058,767 | 95.735 | 1.069 | 2.460 |
| bounded | 16 | 2,187,325 | 2,196,351 | 102.258 | 1.148 | 2.491 |

All six asset proofs have zero canonical padding. Each exact action adds 9,026 bytes. At depth 4, enabling the shared bounded-policy graph adds 1,162,592 proof bytes to the ordinary asset geometry. The ordinary graph has 9,936 rows/292,955 canonical wires; the combined graph has 27,027 rows/701,179 wires. At depth 16 they grow to 12,979/382,871 and 30,070/791,095 respectively. These graphs support different policy scopes, so their timing difference is not an isolated primitive benchmark.

The fresh integrated native ordinary fixture produced a 2,035,605-byte SMZD inner frame: 2,034,581 structured bytes plus 1,024 padding bytes. Its HGPSLC02 carrier is 2,041,389 bytes; proving took 93.444s, verification 1.205s and whole-process peak RSS 2,608,365,568 bytes. Its graph has 27,820 rows and 724,453 wires with 86 public words. Asset proofs have 134 public words, three outputs and restricted policy slots. Native carrier versus asset action sizes, padding, geometry and supported behavior differ; total-byte ratios do not establish a more efficient proof system. The depth 16 combined asset proof exceeds the unchanged native 2 MiB inner-proof cap. It uses only the separately identified 16 MiB candidate parser and is not admitted by native consensus.

The separate administrator proof is 157,253 structured bytes, plus 1,072 public bytes. Proving took 40.504s and verification 0.016s; the final test process passed both changed-intent and damaged-proof rejection. Its whole-process peak RSS was 2,164,260,864 bytes.

The real five-proof ledger lifecycle minted 10 units, froze and unfroze the asset, transferred 4 units and burned 2. It ended with asset debt 8, native fees 5, six consumed nullifiers, two consumed admin action IDs and eleven notes. Truncated spend/admin proofs, frozen transfer/mint/burn in both graph modes, fresh-root nullifier replay and root-cycle admin replay failed atomically. Snapshot restoration retained consumed admin identities. This is an in-memory candidate lifecycle, with disposable fixture secrets; no durable storage, live node restart/reorg, network admission or real asset issuance was exercised.

Focused checks passed: 31 integrated asset tests (two real-proof tests separately invoked), 9 native policy regressions, 7 wallet tests, 12 registry tests, 9 encryption tests, 2 core policy tests and the 7+15 native codec/transport checks. Core and crypto no-std checks passed. The parent scripting evidence remains distinct: all 30 handoff paths and retained 521 formal sources/521 objects/19 qualification files were independently checked. No 521-module recompile or expanded whole-program Rust equivalence campaign was performed.

The asset runtime source identity is `7eab58f56022397bf9de47edb5b4213b93ade238baf45981dddcd5aa281bb85bc30af56825bd18d4c42a32f0b2d1ed9a7e366aee6399711b459dfd5e10087878`. Native and administrator identities differ and are recorded with exact public/CSR, proof, carrier, binary and source hashes in `.agent/stablecoin-v1-20261016/qualification-receipt.json`. That receipt retains process scope, per-case negative checks, projected versus actual bytes and evidence-file hashes. The additive patch manifest pins all preimages and postimages against `scripting-baseline.json`; inherited overlay/scripting source is excluded. An independent 6316-file scope audit found no changes outside the 35 owned source paths.

This completes the bounded inactive candidate and local measurement gates. It is ready for review/integration in that scope. Activation remains blocked on the seven formal and lifecycle obligation families above, authenticated durable wallet/node integration and the explicit G8/production release gates. `SOURCE_LOWERING_CERTIFICATE_COMPLETE` and production authorization remain false for the changed asset relation.

## Reproduction and evidence

For the native Development node and persistent wallet, build the actual executables with:

    CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=$PWD/target-stablecoin cargo build --offline --locked --profile retained-proof -p hegemon-node -p walletd -p wallet --features hegemon-node/development-candidate,walletd/development-assets --bin hegemon-node --bin walletd --bin private-spend

Run `target-stablecoin/retained-proof/walletd --asset-help` for the exact request schemas. `walletd --store PATH --mode create|open --request-file REQUEST.json` reads the passphrase from the first stdin line and performs one bounded JSON operation. Use `asset.address` to register a receiving index before expecting discovery, `asset.credentials` for the current credential witnesses, and `asset.row`/`asset.setup` to produce a public zero-supply descriptor for a fresh disposable Development network. The node's `--print-development-candidate-manifest --development-funding-address ADDRESS --development-assets-json DESCRIPTOR.json` commits that descriptor to the fresh network identity. Issuer and administrator secrets are separate roles. Runtime controls use `asset.admin`; spending uses `asset.prepare`, durable `asset.export`/`asset.submit`, and verified `asset.sync`. Retain the exact manifest and expected genesis with the wallet. Schema18 stores require recovery into a fresh schema19 store.

The current moving-chain runner is the curated tool linked by the final handoff.
Its copied `qualification/run.py` retains the historical TRACE helper it imports.
After inspecting the handoff and using a fresh run name, run from the target root:

```sh
python3 .agent/stablecoin-moving-chain-v1/qualification/run.py \
  --run --root "$PWD" --suite extended --run-name UNIQUE_NAME \
  --usage-floor 60 --coordinator-usage-remaining CURRENT_PERCENT \
  --node target-stablecoin/retained-proof/hegemon-node \
  --walletd target-stablecoin/retained-proof/walletd \
  --private-spend target-stablecoin/retained-proof/private-spend
```

Use one serialized heavy process and the current measured remaining percentage;
keep the approved resource floor and10GiB disk reserve. Inspect the completed
receipt, exact genuine-candidate inventory, fresh readouts and independent review;
a prepared or RUNNING receipt establishes no later acceptance. The lifecycle must
include proving while mining advances, reference-window edges, current controls
and accounting/nullifiers, restart, fresh sync and rollback on actual work.

The harness deliberately isolates its seeds. Shared miners must use
`HEGEMON_SEEDS="hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333"` unless
deliberately rotated, and all miners must share the same seeds to avoid forks.
Keep NTP or chrony enabled because future-skewed PoW timestamps are rejected.

### Historical exact-parent reproduction and provenance

`scripts/check_native_asset_profiles.py --run --with-main-lifecycle` is the
historical exact-parent runner. Its full command additionally supplies a unique
run name, the three binary paths and the coordinator usage value. It controlled
mining to retain an exact inclusion-parent hash, height, note root and registry
root; its old receipts do not establish moving-chain acceptance. The retained
baseline and candidate measurement commands below describe that historical
source and must not be used as a v3 qualification claim.

The worktree baseline is commit `e76a2266ba6d3d49ad3a84dff82a93d32d5b8c23` plus the verified 297-file source overlay SHA256 `565128d392b0083691e95a075a94b7608dcaa9a25a136e33fef478e8d344e5a2`. The new inherited baseline also includes the 30-path scripting bundle manifest SHA256 `3101a67a544f72f9cf7bbaee652a4707607e63a0af4f885d692e34b42912701f`, archive SHA256 `ce04020d9da2547c32c1baaa70239a555b90c2294010145b3547ea1040083636` and acceptance receipt SHA256 `44b9512809c046b78fecd27ff6e56ec32b63467168e429b6af341827e761613e`. All destination and image hashes were checked before application. Inherited overlay and scripting changes are excluded from the stablecoin patch. Local receipts and the living ExecPlan are under `.agent/stablecoin-v1-20261016/`.

Use one Cargo target and builder:

    CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=$PWD/target-stablecoin cargo test --offline --locked --profile retained-proof -p transaction-core asset_registry_v1

    CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=$PWD/target-stablecoin cargo test --offline --locked --profile retained-proof -p synthetic-crypto asset_note_encryption_v1

Build the two measured runners with the same package/feature union, then use fresh receipt, log and artifact paths:

    CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=$PWD/target-stablecoin cargo build --offline --locked --profile retained-proof -p transaction-circuit -p wallet --features transaction-circuit/private-spend-dev-artifacts,wallet/private-spend-dev-artifacts --example asset_spend_v1_artifact --example private_spend_candidate_artifact

    RAYON_NUM_THREADS=2 python3 scripts/measure_stablecoin_v1.py NEW_RECEIPT.json NEW_LOG target-stablecoin/retained-proof/examples/asset_spend_v1_artifact transfer --profile bounded --depth 4 NEW_ARTIFACT_DIRECTORY

Repeat with `--profile ordinary|bounded` and `--depth 4|8|16`. For the native comparison, pass `target-stablecoin/retained-proof/examples/private_spend_candidate_artifact ordinary NEW_ARTIFACT_DIRECTORY` to the same measurement wrapper. The transaction-circuit tests `asset_spend_v1_state::tests::candidate_real_mint_transfer_burn_freeze_and_persisted_replay_lifecycle` and `asset_policy_admin_v1::tests::candidate_admin_proof_roundtrip_and_exact_binding` are deliberately ignored in the normal suite; invoke them individually with `--ignored --exact --nocapture --test-threads=1` and two Rayon threads. `HEGEMON_ASSET_LEDGER_EVIDENCE_DIR` retains the lifecycle's five public proof/action artifacts; `HEGEMON_ASSET_POLICY_ADMIN_PROOF_OUT` and `HEGEMON_ASSET_POLICY_ADMIN_RECEIPT_OUT` retain the administrator proof and measurement receipt.

Run proof executables directly with `RAYON_NUM_THREADS=2` through `scripts/measure_stablecoin_v1.py`. It records the whole child-process peak RSS without requiring `/usr/bin/time` sysctl access. Report proving and verification separately, proof bytes separately from carrier/action bytes, exact source/statement/artifact hashes and graph growth. Native SMZD reserves a fixed padded frame; SMZE structured bytes and padding must be distinguished before comparing them. Credential depths four, eight and sixteen are separate source-derived geometries. Registry depth is fixed at four in V1; that is a limitation, not evidence of arbitrary registry scaling.

The historical native Development action is 1,932,094 bytes, with a 1,931,869-byte carrier and a 1,926,125-byte inner frame. The historical 92.088-second timer covers wallet construction plus export. It is a provenance anchor, not a prover benchmark. The same-run measurement receipts and final readiness report must be read before making compactness or release claims.
