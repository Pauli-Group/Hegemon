# Compile the frozen R1CS into an exact equal-half Section 11 carrier map

This is a living ExecPlan maintained under `.agent/PLANS.md`. It governs only
the isolated source-only artifact in this directory. The repository-wide
production ExecPlan remains authoritative for any implementation or release.

## Purpose / Big Picture

The frozen `HX448C02` mixed-hash diagnostic has an exact macro-R1CS geometry,
but a CFW26 Section 11 input needs two equal, power-of-two halves and square
matrices. This artifact makes the smallest exact arithmetic embedding
reproducible without writing tens of millions of rows: every canonical sparse
entry receives an invertible column map, unused witness positions receive
explicit `x*1=0` constraints, and all remaining rows are fixed empty rows.

The result is useful as a compiler boundary and as a negative baseline. It is
not a production carrier: `HX448C02` still has four host-only predicates, its
macro schedule has no retained expanded coordinate stream, the printed CFW26
construction has unresolved completeness/type defects, and no PCS, complete-ZK
proof, QROM composition, Rust refinement, or proof artifact exists.

## Progress

- [x] (2026-08-22) Read the repository instructions, design/methods/whitepaper,
  production ExecPlan, frozen odd-field compiler, retained relation manifest,
  certificate, tests, and Section 11 source audit.
- [x] (2026-08-22) Pin the exact four upstream odd-field files, their canonical
  JSON identities, source-set digest, mixed-profile geometry, and relation
  digest.
- [x] (2026-08-22) Implement the parameterized equal-half compiler, closed-form
  sparse A/B/C map and inverse, padding schedule, canonical parser, tiny
  positive parity fixture, and adversarial mutations.
- [x] (2026-08-22) Account for all 105 encoded Section 11 oracles without
  inventing a PCS mapping, query schedule, codeword length, or proof bytes.
- [x] (2026-08-22) Add the printed `st2` counterexample and main-form typing
  boundary while keeping completeness/theorem authority false.
- [x] (2026-08-22) Emit retained canonical JSON, run all source-only checks
  twice, record exact hashes below, and hand the bounded artifact to the lead
  agent.

## Surprises & Discoveries

- Observation: fitting source rows into `2*ell` is not by itself sufficient
  when every unused witness coordinate receives a row after the source rows.
  This schedule needs `ell >= m-(n-l)` in addition to fitting `l+1` and `n-l`.
  For the frozen relation, the witness half remains the dominant bound and
  yields `ell=2^25`.
- Observation: the printed Section 11 vector `st2=(0,1,0,...)` extracts the
  linear coefficient rather than evaluating a polynomial at one. The endpoint-
  vanishing polynomial `X^2-X` has printed dot product `-1` even though both
  endpoint evaluations are zero. `pow(1)=(1,1,...)` repairs this local test but
  does not by itself repair or prove the theorem.
- Observation: future all-W64 manifest closure and HX512 semantic widening will
  change the source relation and likely its geometry. The compiler therefore
  exposes a parameterized `project` command, while the retained certificate is
  explicitly stale on any source-relation digest change.

## Decision Log

- Decision: flatten the carrier as `v[0..ell) || w[0..ell)` and keep the source
  constant/public columns in `v` while translating every auxiliary source
  column into the used prefix of `w`.
  Rationale: the map has three disjoint intervals, preserves every matrix lane,
  row, coefficient, and stream identity, and has a closed-form inverse.
  Date/Author: 2026-08-22 / Codex.
- Decision: fix public padding in the canonical input constructor but constrain
  existential witness padding with one `x*1=0` row per element.
  Rationale: public padding is not existential; witness padding is and must not
  be left as a free counterfeit surface.
  Date/Author: 2026-08-22 / Codex.
- Decision: certify a universal bijection for any canonical upstream sparse
  entry while explicitly leaving macro-to-expanded-coordinate refinement open.
  Rationale: the upstream artifact retains exact macro counts but deliberately
  does not retain the 94,551,238-coordinate stream. A compact map cannot create
  missing source-coordinate evidence.
  Date/Author: 2026-08-22 / Codex.
- Decision: retain no expanded matrix and invoke no Cargo, rustc, Lake, build,
  proof, or dependency command.
  Rationale: the disk gate is closed and none of those operations is necessary
  to certify the arithmetic map.
  Date/Author: 2026-08-22 / Codex.

## Outcomes & Retrospective

The bounded source-only carrier compiler is complete and reproducible. The
retained frozen geometry is `ell=n0=2^25`, `2^26` rows/columns, 33,544,279
public zeros, 14,253,029 explicitly constrained witness zeros, 32,398,608 empty
rows, and 123,057,296 carrier nonzeros. The tiny exact R1CS preserves all three
source row evaluations after embedding. Thirteen adversarial internal mutations
and 24 unit tests pass fail-closed. A second `emit` reproduced identical hashes.

This closes only the arithmetic sparse-map definition. It does not close the
frozen source's host-only predicates, macro-to-expanded-coordinate refinement,
production parser padding, the CFW26 printed construction defects, complete
zero knowledge, PCS/IOP/QROM security, verifier refinement, or proof bytes. All
authority flags remain false, and the retained certificate is invalidated by a
future all-W64/HX512 source-relation digest change.

## Context and Orientation

The input directory `.agent/hardening/hvzk-whir-odd-field-r1cs/` retains a
canonical macro-R1CS for the `blake2b448-mixed` negative baseline. Its exact
geometry is `m=20,457,227`, `n=19,311,555`, `l=10,152`, and
`nnz=94,551,238`; the source witness/auxiliary count is `n-l=19,301,403`.

An R1CS row is `(A*z)*(B*z)=C*z`. Source column zero is the constant one,
columns `1..l` are public bits, and columns `l+1..n` are private transport plus
derived auxiliary values. The carrier has `z=(v,w)` with `ell` elements in
each half. Source columns zero through `l` map unchanged; source column `c>l`
maps to `ell+c-(l+1)`. Source rows and matrix names remain unchanged.

## Plan of Work

`compiler.py` strictly parses and hashes the upstream files, derives the
smallest valid power-of-two half, emits the compact mapping/padding/oracle
ledger, and reconstructs retained JSON byte-for-byte. It also exposes
`project --m --n --l --nnz --source-relation-digest` so a later exact successor
can obtain arithmetic geometry without inheriting this frozen identity.

`test_compiler.py` exercises the map on a tiny satisfying R1CS, compares every
source and embedded row evaluation, and rejects mutations to indices, the
constant slot, public/witness padding, row/matrix/coefficient preservation,
duplicate/missing entries, canonical JSON, and relation digests.

## Concrete Steps

From `/Users/pldd/Projects/Reflexivity/Hegemon`, run only:

    PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/cfw26-section11-carrier-compiler/compiler.py emit
    PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/cfw26-section11-carrier-compiler/compiler.py check
    PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/cfw26-section11-carrier-compiler/test_compiler.py
    PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/cfw26-section11-carrier-compiler/compiler.py summary

The parameterized interface can be exercised without retaining output:

    PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/cfw26-section11-carrier-compiler/compiler.py project --m 20457227 --n 19311555 --l 10152 --nnz 94551238 --source-relation-digest 81f88eb0afd355bbd50d90d0760b65e341b4b490a29af3d5e0a8acf1721e42792bd547fd62559263f1c70edf365fb482fde2f88117c3ae98b2360934a3c75254

## Validation and Acceptance

Acceptance requires canonical retained artifacts to reconstruct without byte
drift, all unit tests and internal mutations to pass, the exact frozen counts
above, the oracle ledger `1+78+26=105`, the `X^2-X` printed-`st2`
counterexample, null PCS/proof-byte fields, and every authority flag false.

## Idempotence and Recovery

`emit` is deterministic and safe to rerun. It writes only the two generated
JSON files in this isolated directory. Any upstream byte, relation digest,
geometry, parser schema, or local compiler/test change makes `check` fail until
the change is reviewed and the artifact is deliberately re-emitted. No command
deletes or modifies an upstream file.

## Artifacts and Notes

Final verification reported `24 tests ... OK`, thirteen rejected internal
mutations, and carrier-manifest SHAKE256-512 identity
`9ca447bdb81aa3b90edb1ed60a3b0cf7aa79d93d50dbb90466d93ad114585a3d509c61860e2a03b9c462965f2f30bec7f1af635f2f308e11236f629e51482925`.
The retained source-set SHA-512 is
`f0842f84240e43343a4f4677c8d9c1b8ad7860f24ccb9a03c16b9b390ea8446d818a1ead229375cd6b74f965faa9a67eea93b24a57ca695716389a44431550fd`.

Retained file SHA-512 values are:

- `compiler.py`:
  `d1d14303379231222c62a31dc21ee5315471897307d04ef30999b89e514579604d4962031fe7100d9d0f0d371ebd59b0ae04ece250925024508e814833ac0a33`
- `test_compiler.py`:
  `e7db4936540ff018f051b6d4ca36feb9df4fa792d6be1215c26012609a4195f3c55fbc5e74a7ce122858578a1295eee14f5be96e2411893fbb44569d16d49241`
- `carrier_manifest.json`:
  `888f4a42f6d5b37aab132e2ba60318a5ee08d6b71f69046ade2ce206e5af99ab479c6555b9635e8750afa2d68ea7f3da12ecb2d47ac3882834a33b76c03bb730`
- `certificate.json`:
  `c8a170acfde05345512b2ca23485fb3ff3b7a4b1d6e71a344b7c777ed6c091d9635d30723712d00a9d30ba16c8c02189bb485b8e2e6f1109903fa7211375756c`

Revision note (2026-08-22): completed the carrier compiler, added the
digest-parameterized successor interface and the newly identified printed
`st2` counterexample, ran the full source-only validation, and recorded the
final fail-closed evidence.

## Interfaces and Dependencies

The implementation uses only Python's standard library. `CarrierSpec` and
`derive_equal_half_spec` define geometry; `map_source_entry` and
`unmap_source_entry` are exact inverses over the source image;
`witness_padding_entries` defines each added row; `parameterized_projection`
accepts future geometry plus a canonical 64-byte relation digest. All retained
security/refinement/production fields remain false.
