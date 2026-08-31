# Produce and audit one full SmallWood/BLAKE2b artifact

This ExecPlan is a living document and is maintained according to `.agent/PLANS.md`.
It covers only the diagnostic BLAKE2b-384 artifact lane. It must not be used to
claim strict security or to activate the dormant V5 route without an independent
security-checker decision.

## Purpose / Big Picture

The repository needs one reproducible, self-contained proof byte string for the
maximum two-input/two-output SmallWood relation using the exact BLAKE2b-384
Boolean relation. The artifact must carry its complete statement and proof in
one canonical envelope. A fresh verifier must consume exactly those bytes, bind
the authoritative network/action/statement context, and reject every malformed
or substituted variant. The visible result is a measured artifact and a JSON
manifest; the manifest explicitly remains `prototype_only` until the security
checker authorizes a different posture.

## Progress

- [x] (2026-08-22) Read `AGENTS.md`, `DESIGN.md`, `METHODS.md`, and `.agent/PLANS.md`.
- [x] (2026-08-22) Confirmed the canonical current V5 envelope is 80-byte header +
  672-byte statement + inline proof, with exact-consumption parsing and a
  512 KiB envelope cap.
- [x] (2026-08-22) Added `scripts/run_smallwood_blake2b384_artifact.py`, an
  independent envelope parser, manifest writer, byte counter, fresh-process
  verifier harness, and parser/backend mutation suite.
- [x] (2026-08-22) Added disk and integration fail-closed checks. The harness
  checks the 28 GiB free-space floor before invoking any prover command and
  requires a protected integration marker declaring the compiled BLAKE2b
  relation/profile.
- [x] (2026-08-22) Added a disk-light Python regression for the parser and
  mutation expectations.
- [ ] Generate the actual maximum-shape artifact after the integration marker
  exists and the backend has been independently wired to the BLAKE2b relation.
- [ ] Run the backend verifier twice in fresh processes, run every mutation,
  record exact proof/envelope bytes and SHA-256 digests, and preserve the
  resulting manifest under `artifacts/smallwood-blake2b384/`.
- [ ] Ask the security checker to classify the resulting evidence. Do not set
  strict or production fields from the runner itself.

## Surprises & Discoveries

- Observation: the initial disk report was below the 28 GiB floor, then the
  shared workspace increased to approximately 32.5 GiB free during preparation.
  Evidence: `df -h .` now reports 32 GiB available and the harness reports
  `free_bytes=34883305472`. This opens storage admission, but it does not open
  backend admission.
- Observation: the checked-in BLAKE2b relation remains a semantic/Boolean
  diagnostic surface. Evidence: `smallwood_blake2b384_relation_is_production_authorized()`
  and `smallwood_blake2b384_boolean_relation_is_compiled()` are both false, and
  the required integration marker does not exist. No Cargo/proving run was
  started on that account.
- Observation: the existing V5 envelope's strict transcript label names the
  SHAKE256-448/SHA-512 strict candidate. The runner therefore records the
  BLAKE2b artifact as prototype-only and binds the actual relation schedule
  digest in the envelope's 48-byte relation-binding field; it does not rewrite
  the production envelope or security gate.

## Decision Log

- Decision: keep the existing canonical V5 envelope as the byte boundary and
  add an independent parser/manifest harness around it.
  Rationale: envelope construction and production binding are owned by the
  existing transaction module; duplicating or modifying that security surface
  would create an alias rather than test the shipped bytes.
  Date/Author: 2026-08-22 / Codex.
- Decision: require an external prover and verifier command instead of emitting
  a digest or scalar trace as a fake proof.
  Rationale: semantic relation material and Boolean trace verification do not
  establish a SmallWood proof. The adapter must supply real proof bytes and a
  verifier that consumes them exactly.
  Date/Author: 2026-08-22 / Codex.
- Decision: run no prover command until both disk and integration gates pass.
  Rationale: the large proof run is explicitly gated by storage, and the
  current source has no BLAKE2b proof backend to invoke.
  Date/Author: 2026-08-22 / Codex.

## Outcomes & Retrospective

The byte-level runner is ready and fail-closed. It independently checks header,
statement, proof, relation-binding, byte cap, exact consumption, manifest
digests, two fresh verifier processes, and statement/proof/profile/network/action
mutations. No proof artifact has been generated because the repository has not
yet supplied the required compiled BLAKE2b SmallWood backend marker. The next
contributor can resume by creating the marker only after the real relation/profile
integration and its security review inputs exist, then invoking the exact command
shown below.

## Context and Orientation

`circuits/transaction/src/smallwood_v5_envelope.rs` owns the current canonical
borrowed envelope parser and encoder. Its layout is an 80-byte fixed header,
the 624-byte little-endian 78-word public vector, a 48-byte relation-computed
balance tag, and one inline proof. `circuits/transaction/src/smallwood_blake2b384_semantics.rs`
owns the BLAKE2b-384 semantic schedule and exposes its 48-byte schedule digest,
but currently leaves production authorization false. The new Python runner does
not replace either module: it acts as an independent byte oracle and invokes a
future backend through a narrow command-line adapter.

The integration marker is a repository-relative JSON file with at least these
fields: `boolean_relation_compiled: true`, `profile_integrated: true`,
`profile_id` containing `blake2b`, and `relation_hash_output_bits: 384`. A
`production_authorized` field may remain false while the artifact is reviewed;
the runner never derives strict authority from this marker and never creates it.

## Plan of Work

The prover command must accept `--generate --output PATH --network-id N
--activity-mask 15 --auth-mode SingleKey --maximum-shape` and write one exact
SWV5 envelope. It must construct the maximum two-input/two-output witness,
materialize all active slots, lower the exact BLAKE2b Boolean relation into the
SmallWood backend, and return only after the produced proof verifies locally.
The runner then parses the bytes independently, measures proof and envelope
lengths, and passes the complete authoritative statement and relation binding
to the verifier.

The verifier command must accept `--verify PATH --network-id N --family-id 1
--action-id 7 --relation-binding-hex HEX --statement-hex HEX`. The runner starts
it twice in separate processes to cover restart/fresh-verifier behavior. It
then mutates statement, proof, relation binding, network, profile, version,
action, truncation, trailing bytes, empty proof, and statement length. Parser
mutations must reject before backend work; parsed statement/proof/relation and
network mutations must be rejected by the backend against the authoritative
context.

## Concrete Steps

From `/Users/pldd/Projects/Reflexivity/Hegemon`, first check the gates without
Cargo:

    python3 scripts/run_smallwood_blake2b384_artifact.py check-disk --root .
    test -f .agent/smallwood-blake2b384-proof-backend-ready.json

After the integration owner supplies the marker and the security checker has
approved running the backend, use:

    python3 scripts/run_smallwood_blake2b384_artifact.py generate \
      --root . \
      --integration-marker .agent/smallwood-blake2b384-proof-backend-ready.json \
      --network-id 1213485365 \
      --prover-command 'cargo run -p transaction-circuit --example smallwood_blake2b384_proof_runner --' \
      --verifier-command 'cargo run -p transaction-circuit --example smallwood_blake2b384_proof_runner --'

The default output is `artifacts/smallwood-blake2b384/full-maximum-single-key.swv5`
with the adjacent `.manifest.json`. Reopen it later with:

    python3 scripts/run_smallwood_blake2b384_artifact.py verify \
      --root . \
      --manifest artifacts/smallwood-blake2b384/full-maximum-single-key.manifest.json \
      --verifier-command 'cargo run -p transaction-circuit --example smallwood_blake2b384_proof_runner --'

Do not run either Cargo command while the disk or integration marker gate is
closed. Do not delete shared caches to force the disk gate open.

## Validation and Acceptance

Acceptance requires a real artifact, not a report generated from relation
metadata. The manifest must record `maximum_transaction=true`, two active
inputs, two active outputs, activity mask 15, `SingleKey`, exact statement,
proof, and envelope lengths, and SHA-256 digests of each. The independent
parser must accept the canonical bytes and reject truncation, trailing bytes,
empty proof, oversized proof, unsupported header fields, and noncanonical
statement words. Two fresh verifier processes must accept the canonical bytes.
The mutation suite must report parser rejection for malformed envelope fields
and backend rejection for parsed statement/proof/relation/network substitutions.
The manifest must remain `prototype_only` and `strict_security_authorized=false`.

## Idempotence and Recovery

The runner writes only the requested artifact and manifest paths and uses a
temporary directory for mutations. Rerunning overwrites only those explicit
outputs after a fresh proof and verifier pass. If the prover fails or produces
noncanonical bytes, retain the error and do not weaken the parser or mark the
manifest complete. If disk admission falls below 28 GiB, stop before launching
Cargo and resume after external cleanup or storage expansion.

## Interfaces and Dependencies

The Python harness uses only the standard library. The future prover/verifier
adapter is deliberately process-based so a fresh verifier has no in-memory
state from proving. The canonical Rust envelope remains the source of truth;
the Python parser mirrors its fixed offsets only to detect byte drift. The
relation binding is the exact 48-byte BLAKE2b schedule identity returned by the
relation integration, and the complete statement is passed as authoritative
context rather than copied from mutable proof metadata.
