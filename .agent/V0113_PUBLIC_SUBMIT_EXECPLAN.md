# Implement and qualify the v0.11.3 public submission policy

This living ExecPlan follows `.agent/PLANS.md`. Keep Progress, Surprises & Discoveries, Decision Log and Outcomes & Retrospective current. The initial task was local implementation and qualification. On 2026-11-06 (America/Edmonton), the user explicitly authorized preparing and publishing v0.11.3, deploying to hegemon-dev and hegemon-ovh, verifying operation, and updating the website release links. That authorization covers the release and these destinations; required qualification and existing compatibility boundaries remain in force.

## Purpose / Big Picture

Third-party browser wallets should be able to submit existing client-proved transactions to an explicitly enabled public RPC listener without gaining mining, peer topology or DA upload privileges. Keys, note scanning/decryption, witness construction and proving stay client-side. A successful candidate exposes `--rpc-methods=public-submit`, adds exactly `hegemon_submitAction` to the available safe catalog, charges each submission in a batch, and bounds expensive work without consuming reserved local verification capacity. It preserves current protocol, genesis, transaction/proof bytes, crypto and wallet encryption.

## Progress

- [x] (2026-11-07 UTC) Inspected main checkout, current tags, worktrees and disk. Main checkout is unrelated dirty research work and is untouched.
- [x] Created isolated `/private/tmp/hegemon-v0113-public-submit`, branch `codex/v0.11.3-public-submit`, from v0.11.2 `15c42e687b24d9cb35bb6dbde6061459d6f1242a`.
- [x] Integrated reviewed nonconsensus `af9a05cac18b663832d6bbacce4b634c81937779` as `fd3a6f3d08`; resolved only metadata history conflicts, retaining newer hotfix notes. Existing receipts are historical and require fresh checks.
- [x] Read applicable AGENTS.md, .agent/PLANS.md and DESIGN/METHODS native cutover and independent-proof sections.
- [x] Implemented policy/catalog, transport-IP admission, shared finite read/submission client budgets, dedicated public verifier capacity and response-owned reservations.
- [x] Lean model now covers all four policies, registration/availability, action scope and resource/ownership contracts; generated 718 cases including four real-guard ownership traces. Pinned Lean compilation and standard-axiom audit passed; production Rust execution passed for all 718 generated rows across the two applicable feature configurations (466 rows each, 214 shared). Final default execution passed; the final feature rebuild remains resource-blocked.
- [x] Implemented 15 actual local socket/concurrency/CORS tests; all passed. The real fresh-manifest/wallet/mining lifecycle passed with final release binaries, including public HTTP acceptance and durable restart byte identity.
- [x] Updated product release/version metadata to 0.11.3, launcher, docs and a distinct pending candidate inventory helper; internal Cargo package versions/lockfile intentionally remain byte-identical to v0.11.2. Accepted release/source pins remain unchanged.
- [x] Ran focused Rust/Lean, source and release checks, recording exact successes and non-passes. Final default: 37 public tests (15 real HTTP), 39 compatibility tests, 466 applicable model rows; formal checker 258 tests plus proposition and governance checks. Full formal-crypto, full vectors/policy phases, final feature rebuild and source release authorization remain unresolved as detailed below.
- [x] Prepared the source patch, real four-binary build, validation receipts and concrete rollout checklist. Final commit-bound manifest and delivery files are produced outside source after freezing this plan.
- [ ] Complete the remaining release qualification and independent approval gates before any publication or deployment; no such approval is inferred from this local candidate.

## Surprises & Discoveries

The main checkout is `codex/smallwood-pq128-experiment` at da3135ad933b785e505a8199710142ae5e680593 and has extensive unrelated modifications. The current v0.11.2 tag includes sync, CPU readiness, transport and known-loser fixes, but the reviewed nonconsensus commit was divergent. Only 13 GiB free was observed initially; use a single isolated build cache with jobs 1, no incremental and debug info disabled, never clean concurrent caches.

The current active route is family 1/action 15 PrivateSpend, circuit 12/crypto 7, using the exact pre-mainnet source capability. Bare --dev is not positive production-route evidence. PrivateSpend hides ordinary/HTLC/policy/treasury witness selectors; its public statement cannot establish an ordinary-only hidden branch. The user explicitly confirmed accepting every valid spend supported by the existing PrivateSpend proof, with all checks preserved. No format changes or artificial authority will be introduced.

Existing submit_action obtains both local and shared verifier permits. Public work must not borrow either reservation. The initial design adds a dedicated public lane, so the aggregate bound becomes the unchanged existing three slots plus the configured public capacity (default one). This is a concurrency bound, not a CPU-time cutoff or OS scheduling guarantee.

## Decision Log

Decision: admit the existing common PrivateSpend route and all private modes its unchanged relation validates; reject other explicit action families. Rationale: the user explicitly confirmed this scope after explanation of hidden witness selectors. No ordinary-only hidden-branch filter is claimed. Date: 2026-11-07 UTC.

Decision: use an isolated worktree from the current v0.11.2 tag plus explicitly integrated reviewed fixes. Rationale: preserves live research and all newer maintenance fixes; source identity is distinct. Date: 2026-11-07 UTC.

Decision: ignore all forwarded-address headers in this release and key rate limits only by normalized transport-observed IP. Rationale: this fail-closed contract avoids impersonation and loopback proxy privilege escalation; proxy clients share the proxy bucket. No trusted-proxy forwarding support is claimed. Date: 2026-11-07 UTC.

Decision: use immediate finite admission with no application waiting queue, finite client table and expiry, plus bounded public HTTP workers. Rationale: avoids accumulating expensive requests or unbounded limiter state and permits clear stable denial semantics. Date: 2026-11-07 UTC.

Decision: never rewrite accepted proof-source inventories to make the changed candidate pass. Rationale: actual candidate qualification and historical acceptance differ. Diagnose any source-binding gate failures, and prepare truthful pending candidate inputs if authorization cannot be derived. Date: 2026-11-07 UTC.

## Outcomes & Retrospective

The opt-in policy, finite admission, public verifier lane, real HTTP tests, Lean model/conformance, source obligations, integration documentation and release preparation tooling are implemented. The final release binaries accepted a fresh client-proved PrivateSpend over public HTTP, retained the unchanged 177,290-byte action and 171,281-byte proof across restart, and rejected seven negative controls without changing canonical or pending state. All owned lifecycle processes were reaped. The single observed proving time was 42.547 seconds and public submission took 0.720 seconds; these are local measurements, not service capacity guarantees.

This is a locally tested candidate, not a fully qualified release. The complete formal-crypto gate refused its unchanged 8 GiB free-space requirement (about 5 GiB available); an audited historical cache is incomplete and contains modified mathlib sources. Full formal-core vectors/policy phases, the final feature rebuild, all release parser/native-backend reference tests, all-platform packages and intended-hardware load qualification remain open. The exact historical source-successor checker rejects this new Rust/Cargo inventory, and the binary security wrapper cannot attest the production profile. Its source/dependency scans and all four binary forbidden-symbol scans were clean; its generic forbidden-primitives summary counts the two attestation failures and is not evidence of an identified ECC primitive. All 121 independent reviews remain pending. Historical pins and profiles were preserved. No production approval, push, tag, publication or deployment is claimed.

## Context and Orientation

`node/src/native/mod.rs` defines CLI/config/policy and node fields. `util.rs` contains policy resolution and method catalog. `rpc.rs` parses HTTP JSON-RPC, runs blocking dispatch and invokes `NativeNode::submit_action`; `service.rs` constructs the Axum server. `node_impl.rs` contains decoding, authorization, proof/state checks and staging. A reservation is an owned permit that limits simultaneous work; it must remain in the blocking closure until that work ends even if the HTTP client disconnects. `public_admission.rs` will hold finite public counters and client accounting. Existing peer/local/mining limits remain unchanged.

`formal/lean/Hegemon/Native/RpcAdmission.lean` currently models only safe/unsafe despite production pool support. Extend it honestly, including registration/availability and any production state transitions. `GenerateRpcAdmissionVectors.lean` emits test vectors; Rust tests must call actual production functions. `scripts/hegemon_formal_core` checks source/call-order/result and provenance obligations. Mathematical model proofs do not prove socket identity, proxy deployment, scheduling, wall-clock/RSS, universal denial-of-service resistance or privacy.

Release source `e2fcbe4df99025d3b955d5053ebc1f21436db6f2` is the v0.11.2 artifact build source; tag commit 15c42e binds artifacts. `config/v0112-release-artifacts.json` and published binaries/tags stay historical. New outputs need independent version, source tree digest, binary hashes and qualifications.

## Plan of Work

Milestone 1 establishes a reviewed source baseline and separates writes. Completed by source inspection and worktree creation. Root coordinates integration and ExecPlan. Workers exclusively own RPC config/dispatch, public admission/node implementation, Lean/conformance, release/docs/launcher and separate HTTP tests; read-only fixture investigation is independent.

Milestone 2 implements public policy and finite admission. Maintain auto/empty default safe and external unsafe/pool refusal. Catalog must represent registered and capability-available dispatch; no DA upload or unrelated action family enters the public route. Normalize IPv4-mapped IPv6. Charge each submit item before expensive verification and gate public listener work before creating unlimited blocking workers. Stable capacity and rate denials must distinguish failure from uncertain lost response. Public submit uses its owned lane while the old local path remains unchanged.

Milestone 3 proves and tests the implementation contract. Lean proves exact policy delta, compatibility and external behavior, discovery agreement and resource bounds/release ownership. Actual Rust functions consume generated vectors. Local HTTP tests use temporary state and loopback sockets, cover policies, batches, malformed/oversize/inactive/unsupported input, headers, CORS, concurrency/cancellation and no mutation. A positive route must use genuine existing source authority and state, never test-only route activation. Backend-only fixtures are labeled as such.

Milestone 4 prepares release 0.11.3 and completes qualification. Update software versions, launcher and operator/wallet docs without changing crypto identifiers. Run required gates with logs outside source. Record gate failures honestly, not as completed qualification. Produce a candidate manifest with actual identities and release checklist; publication and deployment remain separate decisions.

## Concrete Steps

All commands run in `/private/tmp/hegemon-v0113-public-submit` unless specified. Inspect `git diff --check`, `git diff --stat`, and candidate status. Use `CARGO_TARGET_DIR=/private/tmp/hegemon-v0113-public-build`, `CARGO_BUILD_JOBS=1`, `CARGO_INCREMENTAL=0`, `CARGO_PROFILE_TEST_DEBUG=0` for the isolated Rust build; check `df -h` before expensive work. Exact selected commands and outputs will be recorded as toolchain availability is verified. Lean uses its pinned toolchain and isolated output, not concurrent build artifacts. Preserve source, logs and candidate artifacts; never delete existing state or caches to gain disk.

## Validation and Acceptance

Acceptance requires production policy tests and actual socket tests, generated Lean vectors against production helpers, release formal/source checks and a genuine authorized valid transaction through public HTTP with unchanged action identity/proof bytes. Invalid/wrong network/inactive/unsupported/malformed/oversized cases must not stage an action. Public saturation must leave local permits available under explicitly controlled test conditions; cancel/disconnect cannot release a permit before worker completion or leak it afterward. CORS default remains closed and explicit origins behave as documented. The final evidence states exact scope and remaining limits; a failing authority gate prevents claiming a qualified release.

## Idempotence and Recovery

The isolated source and disposable test state make checks repeatable. Do not change live nodes, databases, wallets, credentials, backups or operator services. Stop only owned test processes. Keep historical pins and artifacts unchanged. Rollback of opt-in RPC behavior consists of reverting this patch or restarting a separately approved deployment with safe policy; there is no data migration or coordinated activation.

## Artifacts and Notes

Candidate source, tests, plan and docs reside in the isolated worktree. Validation logs and build outputs use distinct `/private/tmp/hegemon-v0113-*` paths. Final patch and source manifest will be added after integration. The final release checklist separates local implementation, local qualification, independent/security approval, publication and host deployment.

## Interfaces and Dependencies

Reuse Axum 0.7 Request/ConnectInfo, Tokio owned semaphore permits and spawn_blocking, serde JSON, existing proof/source authorization and mempool staging. No new server-side wallet/prover, proof format or cryptographic dependency. Public admission config and RAII token APIs are coordinated directly between the RPC and admission workers. The caller passes only transport-derived normalized IP; all forwarded headers are ignored. Public action route selection remains separate from proof authority.

Revision 2026-11-07 UTC: initial plan records verified baseline, source/privacy limitations, ownership, bounded admission design and honest acceptance requirements.

Revision 2026-11-07 UTC: user confirmed the unchanged common PrivateSpend proof and its supported spending rules.

Revision 2026-11-07 UTC: recorded implementation and Lean completion; review fixes cover preparse charging, strict envelopes, GET admission, response-body permit ownership and direct production verifier-lane separation. General defaults are 60 requests/min/IP, 6 submissions/min/IP, 1024 clients/600s idle expiry, four request workers, one public verifier, eight batch items and 8 MiB response retention.

Revision 2026-11-07 UTC: remote read-only tag verification returned v0.11.2=15c42e687b24d9cb35bb6dbde6061459d6f1242a and no v0.11.3 tag. Preserved all tags/artifacts. Formal-core cache source files (Cargo.toml/lock/lib/main) were byte-identical to the reviewed-fixes baseline before read-only optimized diagnostic reuse; final checker is being rebuilt after the explicit changed-Lean source digest renewal. All 380 Lean source files were compared against the copied reviewed cache; only RpcAdmission and its generator differ. APFS clone copy into this worktree preserves independent mutable cache ownership.

Revision 2026-11-07 UTC: prepared a separate APFS-cloned release dependency cache from the reviewed-fixes build. Cargo will revalidate/rebuild it for this exact candidate; copied historical binaries are cache inputs only and must never be inventoried as new artifacts. The actual release build and binary/version/hash verification remain required.

Revision 2026-11-07 UTC: critical compatibility correction. `circuits/transaction/src/private_spend.rs::relation_digest` hashes all Cargo.lock bytes. Initial internal package version edits would have changed the relation identity and disabled the intended route. Stopped the unfinished release build (exit130), restored the exact baseline Cargo.lock and four package manifests, and retained product RELEASE_VERSION0.11.3 outside the relation inventory. Lock SHA256 is1c243bf3858f4ee22fa4441c7a2ee6d49b16d264147b0f3a2de845e760821719. Internal node/wallet/walletd versions remain0.10.0 andprotocol-versioning0.1.0, as required for unchanged proof identity. No incompatible binary was qualified or deployed; affected compilation/tests will be redone. Candidate helper/docs are being corrected to enforce this boundary.

Revision 2026-11-07 UTC: actual no-default-feature release node built with the restored frozen lock in 6m43s; reports hegemon-node0.11.3 and SHA256866e13265730715d59ca21ee88dcf4f4a571a5d5b00e5e0b239a2f804d1979b4. Backend-only runner passed five frozen valid proofs plus30negative controls, recording wait4 peak RSS. Positive processes took0.375–0.411s and39.3–40.3MiB peakRSS during concurrent compilation; this is local backend measurement, not service-hardware capacity or state acceptance. Actual HTTP15/15 and existing RPC compatibility39/39 pass; current feature conformance build remains in progress. The Lean full source build/axiom audit passed2771theorems with no unwaived dependencies. Current dependency audit passed0blocking,4nonblocking maintenance notices. Full formal-crypto refused its8GiB cold requirement at5.4GiB free; existing mathlib cache audit found2471/8264compiled modules and2modified source files, so no unsafe cache reuse or download was attempted. Historical source-successor checker rejects the new candidate Rust/Cargo path set; accepted pins remain unchanged.

Revision 2026-11-07 UTC: final default node test binary `hegemon_node-5b7a46bb1ab1af34` built successfully and passed 37 public tests (including all 15 actual socket cases), 39 compatibility cases and its 466 applicable RPC vector rows. The earlier feature binary passed its 466 applicable rows; together these cover the 718-row corpus, with 214 common rows. A final feature rebuild was interrupted at the disk reserve; this is not a final feature-build pass. Current release node SHA-256 is f74a05394392eb24f1f20f9c5c9ac808b50ad146b47c8f520d2d14c86979434c; all five backend proofs and 30 negative controls passed again.

Revision 2026-11-07 UTC: formal checker/source qualification completed: 258 tests plus the separate proposition check; 121 blueprint nodes, 262 bindings, 198 result obligations, 153 ordering constraints and 128 dominance constraints. All 121 independent reviews remain pending. Claims and active-goal audits retain 2,771 roots and the historical 50% assumption-closure boundary. Formal source checks now enforce exact public guards, accounting conditions, error propagation and receiver identity without accepting arbitrary macro/short-circuit calls. Source receipt: `/private/tmp/hegemon-v0113-public-formal/formal-admission-final-receipt.json`.

Revision 2026-11-07 UTC: the first real-time fixture was stopped at height 28 because normal retargeting makes 121-block maturity exceed its bounded run. The second historical-timestamp fixture stopped at the 4 GiB disk reserve. Both receipts are NON_PASS and all owned processes were reaped. All compiler processes were then stopped; only this task-owned debug cache .rlib/.rmeta files were reclaimed (835,848,836 bytes), retaining every executable, proof, source and receipt and verifying executable hashes unchanged. `/private/tmp/hegemon-v0113-compiler-cache-reclaim.json` records the exact files. No user/operator state was removed. The normal four-binary build wrapper also stopped at the reserve; its prior completed individually built binaries remain available. The full formal-crypto gate remains blocked by its unchanged 8 GiB requirement.

Revision 2026-11-07 UTC: the added explicit ignored fixture builder creates a new database through production source authority, real reward construction, real PoW and ordinary import, with only protocol-valid historical timestamps selected at 67-second spacing before sealing. No source/test authority or scheduled difficulty is overridden, and no state rows are inserted directly. The third lifecycle run at `/private/tmp/hegemon-v0113-public-lifecycle-run3` has completed all 121 real imports in 177.48 seconds; the actual release binary replayed the exact fixture tip and the real client proof is in progress. This is not a real-time mining benchmark. Final public acceptance/restart byte comparison remains pending at this checkpoint.


Revision 2026-11-07 UTC: final lifecycle receipt `/private/tmp/hegemon-v0113-public-lifecycle-final/receipt.json` is PASS_FRESH_PUBLIC_SUBMIT_CANDIDATE_LIFECYCLE with seven controls, exact tip replay, exact retained action/proof bytes and all owned processes reaped. The normal four-binary build completed successfully after the bounded failed attempt. Final node SHA-256 remains f74a05394392eb24f1f20f9c5c9ac808b50ad146b47c8f520d2d14c86979434c. The delivery report, scoped patch, commit/source identity, actual artifact checksums and honest open-gate inventory are written to `/private/tmp/hegemon-v0113-delivery/`. Formal metadata and all relation-digest inputs remain unchanged by this final documentation revision.


## Shipping continuation (user-authorized 2026-11-06)

The user requested: “Ship it. Get the release ready. Deploy on hegemon-dev and hegemon-ovh, make sure it works. Publish and update the v0.11.2 on the website to v0.11.3”. Continue through publication and both deployments without a second approval request for the same scope. Preserve live node/wallet data, historical releases and rollback binaries.

Live readback found both hosts running v0.11.2 source 1e56a5c8f97eb6f8abf3e79a728849272c42dd0d (binary SHA256 d2c35897f3355f691e1b6498fd269cbdede48542601b5027ce4d4c7852478d0a), with synchronized clocks, matching genesis/chain and common height 11292. This source descends the original v0.11.2 tag and contains additional sync-control/body-backpressure and release-runner fixes. Merge that deployed lineage into the candidate before release; never downgrade the existing fix. Rust sources merge automatically; the three formal metadata files require preserving both changed obligation sets and renewed fingerprints. The 41 literal proof-relation inputs must remain unchanged.

Build and qualification lanes use isolated owned paths with one compiler job and explicit disk guards. Root coordinates release integration, Git operations, host changes and publication; the formal worker owns the three formal metadata files and formal qualification; the release worker owns additive v0.11.3 source authorization/consumer/packaging tools; an independent reviewer checks the composed runtime and new authority. Historical v0.11.2 checker/config/artifact pins remain unchanged. Independent review acceptance must be an actual review of exact inputs, never a fabricated prior approval.

The current website is served from hegemon-ovh:/var/www/hegemon. Its deployed homepage contains newer visual changes than private repository main. Preserve those live bytes and change only current release references after v0.11.3 assets exist. Prepared exact-delta payload and preimage hashes are in /private/tmp/hegemon-v0113-ship-website; the private website repository gets a separate narrow source commit. Never overwrite the live homepage with the obsolete public monorepo website.

Deployment order is dev then OVH, verifying loaded executable hash, v0.11.3 identity, unchanged chain/genesis/proof parameters and state path, peers/sync/mining posture, shared canonical hashes and normal progress. Save exact units/environment hashes, old executable and coherent state backup/normal shutdown evidence for rollback. Only change the approved node service; operator wallets, credential supervisors and financial flows are not release test fixtures. Current operator RPC is unsafe on loopback; preserve it pending the user's optional public-endpoint preference so mining controls remain available.
