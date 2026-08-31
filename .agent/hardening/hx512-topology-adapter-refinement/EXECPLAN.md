# Certify the HX512 topology-to-adapter refinement

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must remain current. It follows `.agent/PLANS.md` from the repository root.

## Purpose / Big Picture

Hegemon needs independent evidence that the executable SmallWood adapter is the same K=1024 radix-4 BLAKE2b-512 relation described by the frozen topology compiler. A copied row count or digest is not enough: a reviewer must be able to enumerate every topology cell and operation, find its executable polynomial identity and witness assignment, replay every dependency and public target, and independently compare every hash result with RFC 7693.

The checker in this directory is intentionally fail-closed. It currently reports `qualified=false`: the adapter now exposes a rich feature-only certificate surface, but the disjoint live iterator replay, post-fixture topology replay, retained RFC evidence, and grammar-owned all-80 mode/mask seam do not yet exist. No proof profile, verifier, or release manifest may treat the hash topology as refined until those checks pass.

## Progress

- [x] (2026-08-22) Read `AGENTS.md`, `.agent/PLANS.md`, and the active transaction-proof portions of `README.md`, `DESIGN.md`, and `METHODS.md` through the parent implementation campaign.
- [x] (2026-08-22) Pin the post-fixture grammar baseline: whole SHA-512 `e58ec353...986c`, pre-test-support prefix `b9614b6a...0f6d`, feature/test suffix `ce6d7127...4ccf` at byte 133,958, plus Cargo SHA-512 `801047ea...b628c8`; retain topology SHA-512 `a4b7c3e5...a9a0` and the final stablecoin source/transition SHA-256 pair.
- [x] (2026-08-22) Pin the exact K=1024 hash geometry: 95 calls, 226 maximum compressions, 11,892 base rows, 12,177,408 cells, 2,500 explicit padding cells, and 285,744 operations.
- [x] (2026-08-22) Implement a dependency-free checker that rejects K/degree drift, frozen-source drift, canonical-index execution, absent topology operation/dependency/source/target consumption, absent public refinement maps, and absent retained evidence.
- [x] (2026-08-22) Implement adversarial source-only tests, including source mutation, forward-call ordering, cycle rejection, RFC digest recomputation, secret-shape variation, all-80 classification requirements, and concrete map-record flip/drop/duplicate failures.
- [x] (2026-08-22) Remove JSON-only qualification: retained booleans and zero counts are non-authoritative, and an in-process public-iterator replay is mandatory.
- [x] (2026-08-22) Source-audit the adapter owner's feature-only immutable operation/cell/dependency/source/digest-export/target/identity/CSR/partition surfaces; this does not substitute for executing them.
- [x] (2026-08-22) Retain the fail-closed source-only verdict at quiescent adapter SHA-512 `f750aef1...a9518`: the certificate surface is present, while live iterator replay/evidence, post-fixture topology replay, and the grammar-owned all-80 mode/mask API remain absent.
- [ ] Add a grammar-owned 80-case mode/mask fixture seam and replay all cases through both the materializer and adapter, with exactly 26 accepts and 54 rejects.
- [ ] Consume the adapter owner's public immutable iterators in a disjoint Rust harness.
- [ ] Generate `refinement_evidence.json` from two distinct secret assignments for every five authorization modes and all Disabled/Mint/Burn directions.
- [ ] Independently replay all 285,744 operation assignments, all 12,177,408 cell assignments, RFC digests for 2 x 5 x 3 x 95 cases, and the explicit non-hash row partition.
- [ ] Run the package-level Rust checker and retain a qualifying certificate only if every independent check passes.

## Surprises & Discoveries

- Observation: the adapter initially used K=64 while the frozen topology and fresh engine use K=1024.
  Evidence: `smallwood_hx512_adapter.rs` previously declared `HX512_ADAPTER_PACKING_FACTOR = 64`; the owner has since changed it to alias `HX512_RADIX4_PACKING_FACTOR`, but no complete mapping certificate exists yet.

- Observation: canonical hash call IDs are not an execution order.
  Evidence: nullifier call 4 depends on calls 72, 77, or 78 depending on authorization mode; call 5 depends on 73 or 77. The topology compiler topologically sorts the expanded atom graph while retaining canonical IDs. Any adapter loop that requires `call.index == prior_digests.len()` is unsound.

- Observation: the adapter can copy topology rows, cells, and digest into its geometry without lowering one topology operation.
  Evidence: the current source assigns `audited_topology_rows`, `audited_topology_cells`, and `audited_topology_digest_sha512`; the independent checker therefore treats metadata-only binding as a blocker.

- Observation: the adapter now exposes polynomial templates, logical identities, semantic-linear/CSR records, lazy cell producers, operation/source/message/digest-export/public-target mappings, constant provenance, and packed-row partitions only under the evidence feature.
  Evidence: `Hx512TopologyRefinementCertificate`, `logical_identities()`, `cells()`, `packed_gate_refinements()`, and `csr_constraint_refinements()` are present. Their existence is source-shape evidence only until the disjoint harness enumerates and evaluates them.

- Observation: source-only replay found the active adapter now follows the topology event stream rather than canonical call-index order, but an older private dead-code compiler still contains the rejected numeric-index assumption.
  Evidence: `compile_radix4_hash_calls` merges compression-message and operation events and consumes `OperationRecord::dependencies`; `compile_typed_hash_calls` remains `#[allow(dead_code)]` and requires `call.index == per_call_mode_digests.len()`.

- Observation: caller booleans and copied zero counts cannot authenticate a 12,177,408-cell refinement.
  Evidence: an adversarial canonical JSON could previously satisfy the schema without enumerating a public iterator. The checker now rejects all retained JSON unless a disjoint live replay supplies independently recomputed concrete stream commitments.

- Observation: the previous grammar whole-file hash does not authenticate a recoverable old production-prefix snapshot.
  Evidence: the current prefix/test-support split was independently derived at byte 133,958, but no pre-fixture file was retained. The current prefix is therefore a new freeze; old-prefix byte equality is unproved rather than inferred from owner intent.

- Observation: the 30 accepted mode/stable/secret fixtures cannot establish the full authorization mask language.
  Evidence: the grammar has a static 5 x 16 table test with 26 accepts and 54 rejects, but the evidence feature has no public grammar-owned all-80 constructor. Exact refinement requires live materializer/adapter outcomes for every pair.

## Decision Log

- Decision: do not edit either owner module from this hardening lane.
  Rationale: the topology is frozen and the adapter owner is actively implementing the bridge. Independent evidence is stronger when the checker is disjoint from the implementation it assesses.
  Date/Author: 2026-08-22 / Codex.

- Decision: require K=1024, maximum degree 6, and zero auxiliary words.
  Rationale: these are the fresh HX512 engine preflight parameters. The legacy SMZ2 K=64 path is a distinct rejected arithmetization and cannot carry the successor relation.
  Date/Author: 2026-08-22 / Codex.

- Decision: retain 11,892 as the hash-base row count only.
  Rationale: the complete adapter adds separately compiled non-hash transaction rows. Final engine row count `R` must be derived from the complete adapter rather than relabeling the topology base.
  Date/Author: 2026-08-22 / Codex.

- Decision: require two distinct secret variants for every mode and stable direction.
  Rationale: one satisfying witness cannot demonstrate secret-independent topology. The checker requires identical adapter shape digests while the test-only secret fingerprints differ.
  Date/Author: 2026-08-22 / Codex.

- Decision: independently recompute BLAKE2b-512 from retained message and personalization bytes.
  Rationale: trusting an adapter-supplied `all_digests_match_rfc` boolean would not establish RFC parity. The checker uses Python's conventional `hashlib.blake2b` oracle for every retained call observation.
  Date/Author: 2026-08-22 / Codex.

- Decision: require one normalized record per topology operation containing its exact nonempty emitted polynomial-identity set, rather than assuming one scalar identity per word operation.
  Rationale: a word operation may emit multiple digit, carry, range, or equality identities. Acceptance requires total operation coverage, no extra topology identities, exact output/carry/dependency/cell maps, and zero residual for every emitted polynomial.
  Date/Author: 2026-08-22 / Codex.

- Decision: obtain the 30 deterministic replay fixtures through an off-by-default `hx512-refinement-evidence` feature or package-owned unit-test hook, and forbid that feature in production release builds.
  Rationale: an external integration crate cannot access a `#[cfg(test)] pub(crate)` helper, and duplicating transaction grammar in the adapter or checker would create a second authority. Synthetic evidence fixtures are test support only.
  Date/Author: 2026-08-22 / Codex.

- Decision: require an additional live 80-case mode/mask classification replay.
  Rationale: the 30 fixture matrix contains accepted representative transactions. Static-table inspection cannot prove the adapter accepts all 26 allowed pairs and rejects all 54 disallowed pairs.
  Date/Author: 2026-08-22 / Codex.

## Outcomes & Retrospective

The bounded checker and mutation suite are implemented. The refinement result itself remains negative, as intended: no disjoint Rust iterator replay or `refinement_evidence.json` exists, topology has not been replayed after the fixture seam, and the grammar-owned all-80 classification seam is absent. The current post-fixture grammar and Cargo hashes are pinned as a new baseline; historical prefix equality is not claimed. No production or relation-complete flag changed.

## Context and Orientation

`circuits/transaction/src/hx512_production_relation.rs` is the frozen typed source registry and exact per-mode hash recipe grammar. `circuits/transaction/src/smallwood_hx512_topology.rs` turns that registry into a K=1024 radix-4 operation DAG, explicit row/cell layout, source bindings, public digest targets, and stable shape digest. `circuits/transaction/src/smallwood_hx512_adapter.rs` is the executable polynomial relation under construction. The fresh SmallWood engine selector is `DirectRadix4Packed1024Hx512Candidate`; it is distinct from retained SMZ2 paths.

A “refinement” here means a checked correspondence from each topology value to the adapter witness and from each topology operation to an executable polynomial identity, preserving all dependencies and outputs. The non-hash transaction relation must occupy a separately named row partition. A digest copied from the topology compiler into adapter metadata does not establish this correspondence.

## Plan of Work

Keep `contract.json` limited to frozen inputs, exact geometry, known forward dependencies, and required public capability names. Keep `check_refinement.py` dependency-free and source-safe. It must first verify immutable source hashes, then verify the topology API and adapter preflight, then consume a retained evidence artifact emitted exclusively through the public adapter API.

The adapter owner must expose immutable iteration or query methods for operation assignments, cell assignments, dependency assignments, message/source bindings, digest targets, row-zero assignments, constant provenance, the non-hash row range, RFC oracle observations, and secret-independent shape. The checker must not reach into private Rust fields or duplicate the adapter compiler.

Add a small external Rust replay harness in this directory once the 80-case grammar seam lands. It will compile two valid assignments for every authorization mode and stable direction; replay all 80 authorization mode/mask classifications; query the public maps lazily; stream-check every topology entry without allocating a 12-million-record vector; evaluate every emitted polynomial; and emit canonical JSON only after all bijections and edge maps pass. Python then independently recomputes every retained RFC digest and confirms exact source hashes and geometry. The command-line gate must invoke this harness directly; it must never accept a replay JSON supplied by the adapter or caller as a substitute.

## Concrete Steps

From `/Users/pldd/Projects/Reflexivity/Hegemon`, run:

    PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/hx512-topology-adapter-refinement/check_refinement.py --expect-blocked
    PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/hx512-topology-adapter-refinement/test_refinement.py
    git diff --check -- .agent/hardening/hx512-topology-adapter-refinement

The first command currently exits zero only with `--expect-blocked` and prints `qualified=false`. Without that option it must exit nonzero until the full evidence exists. The unit test command must pass the complete source-only mutation suite at the approved post-fixture pins.

After the public adapter bridge and evidence emitter exist, run the checker without `--expect-blocked`; expect `qualified=true`, zero blockers, and `production_authorized=false`. Then run the package-level external Rust check using the already-built workspace target; do not start a proof build from this lane.

## Validation and Acceptance

Acceptance requires all frozen source pins to match; K=1024, degree 6, and auxiliary count zero; the exact 95/226/11,892/12,177,408/2,500/285,744 geometry; one and only one executable identity and assignment for each topology operation; one and only one producer/assignment for each topology cell; complete dependency, message/source, digest-target, and row-zero maps; no unconsumed or duplicate cells; no private witness value embedded as a constant; and an explicit disjoint non-hash row range.

The adapter must execute calls in the topology DAG order rather than call-index order and must retain canonical call IDs. Cycle and forward-dependency mutations must reject. For each of five authorization modes, three stable directions, and two distinct secret variants, all 95 adapter digests must equal independent RFC 7693 BLAKE2b-512 results using exact message and personalization bytes. All 30 assignments must have one identical adapter shape digest while each paired secret fingerprint differs.

Separately, the live harness must obtain all 80 mode/mask cases from the grammar-owned feature seam, invoke both grammar materialization and adapter compilation for each, and observe exactly the same 26 accepts and 54 rejects. A static acceptance table or caller-supplied outcome booleans cannot satisfy this gate.

Passing this checker establishes only topology-to-adapter refinement for the frozen hash base. It does not establish the exact complete transaction relation, complete zero knowledge, composed PQ/QROM security, proof bytes, verifier refinement, consensus binding, or production authorization.

## Idempotence and Recovery

The Python checker is read-only. Tests write only inside automatically removed temporary directories. Source drift and malformed evidence fail before qualification. The future evidence emitter must build its complete result in memory and replace only `refinement_evidence.json` after successful readback. No checkout, reset, cleanup, route activation, proof build, or network operation is permitted here.

## Artifacts and Notes

`contract.json` is the immutable input contract. `check_refinement.py` is the gate. `test_refinement.py` is the adversarial mutation suite. `refinement_evidence.json` is intentionally absent until the public adapter API can produce a complete independently replayable record.

## Interfaces and Dependencies

The checker requires public adapter capabilities equivalent to the names in `contract.json`: the refinement certificate; operation/cell/dependency/source/message/digest-export/public-target/padding maps; exact polynomial templates and logical/linear/CSR identities; constant provenance; public-bit bindings; packed-row ownership; and explicit hash/non-hash partitions. Equivalent names may replace these only if this independent checker consumes the same information without private-field access. The grammar must separately expose both `hx512_refinement_fixtures()` and a grammar-owned all-80 mode/mask constructor under the same release-forbidden evidence feature.

Revision note (2026-08-22): created the disjoint fail-closed refinement lane after freezing the 95-call K=1024 topology and discovering both the legacy K=64 adapter seam and forward canonical call dependencies.
