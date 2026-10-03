# RP05 proof package

This directory is the maintained Lean-facing entry point for the four RP05
results. A fresh checkout can inspect the exact source snapshot, verify its
transitive imports and external Mathlib/Lean boundary, then compile the public
aliases from one source root. The aliases preserve the existing theorem
constants; this package does not change production authorization.

## Purpose and orientation

`Rp05/Soundness.lean`, `Rp05/Privacy.lean`, `Rp05/Authorization.lean`, and
`Rp05/Conservation.lean` are the maintained public names. Their source theorems
remain in the retained extraction, privacy, authorization, and supply trees;
`source-manifest.json` records those original paths and the byte hashes of the
staged copies. `generated/Sources/` is the single Lean source root used by the
package builder. The source list is the transitive import closure of the four
public modules, not a copy of every RP05 experiment in the working tree.

Imports not supplied by that project closure are external imports. The manifest
records every such directly imported module, its current OLean hash, and the
Lean toolchain, Lake file, and Lake lockfile hashes. Lake supplies those
external OLean files during checking and compilation. Thus the project-source
snapshot is self-contained, while the exact compiler and library boundary is
still explicit and verified.

The public constants are:

- `HegemonCrypto.SmallWood.Rp05.soundness`
- `HegemonCrypto.SmallWood.Rp05.zero_knowledge`
- `HegemonCrypto.SmallWood.Rp05.authorization`
- `HegemonCrypto.SmallWood.Rp05.conservation`

The privacy wrapper additionally exports `simulator_witness_independence`,
`zero_knowledge_loss_bound`, and `zero_knowledge_lifetime_cap`. The older
two-witness result remains available as `privacy_two_witness` and the
backwards-compatible `privacy` alias. The authorization wrapper retains
`authorization_nullifier_consistency`; the current credential/history join is
separate from that pairwise claim. See the exact scope in
[`RP05_INDEPENDENT_REVIEW_RESOLUTIONS.md`](../../docs/crypto/RP05_INDEPENDENT_REVIEW_RESOLUTIONS.md).

The public wrappers use equality checks against their fully qualified source
theorems. Their names do not assert universal Rust/verifier refinement,
human ownership, or network activation. The new public joins reuse the
existing checked reductions without changing transaction-proof bytes.

## Fresh-checkout workflow

Run these commands from the repository root. A compatible Lean toolchain and
the locked Lake dependencies in `formal/crypto/` must be available first. If a
fresh environment has not populated Mathlib's cache, use the repository's
normal Lake dependency/cache setup; do not change `lean-toolchain`, the Lake
manifest, or dependency revisions to make a check pass.

    python3 -B scripts/rp05_proof_package.py inspect
    python3 -B scripts/rp05_proof_package.py check-source
    python3 -B scripts/rp05_proof_package.py build
    python3 -B scripts/rp05_proof_package.py check
    python3 -m unittest scripts/test_rp05_proof_package.py

`inspect` prints the four roots, source and external-import counts, and the
external module boundary. `check-source` verifies every staged SHA-256, verifies
that the recorded source closure and external import set are exact, and checks
the external OLean pins against `lake env`. `build` compiles any module whose
source, direct-import OLean hashes, or Lean executable/version differs from the
local package build state. It may adopt a retained object only when a successful
strict DAG receipt binds that exact source path and hash, compiler hash,
direct-import object hashes, unchanged pre/post inputs, and output hash.
Retained runs must stay within the package's 16-GiB memory ceiling; successful
receipts produced with lower memory ceilings remain reusable. Dependencies
compile or validate before their importers. `check` is read-only:
it requires every package OLean and state entry to match the current
source/import/compiler pins. Both commands cover the four public wrappers,
which checks their exact theorem aliases in Lean's kernel. A successful `check`
prints `PASS read-only RP05 package check`.

Before package-local cache or retained-receipt reuse, `build` also attempts to
reuse the 257 unchanged original `formal/crypto/` and `formal/lean/` objects.
It runs grouped `lake --rehash --no-build --no-cache build +Module:olean`
checks, bisecting failed groups, and only adopts an object when its original
and staged source hashes, direct-import object hashes, Lean/Lake/toolchain
pins, full Lake trace, option trace, and pre/post OLean hashes all match. These
general-library objects retain their original Lake compilation settings; an
opaque default-options hash is recorded just like an explicit option list.
That provenance check is intentionally distinct from the strict compiler flags
used for newly compiled package modules and does not relax the four public
wrapper checks. A validated object is copied into `formal/rp05/build/` and its
copied hash is checked before build state is credited. The no-build Lake
validation does not rebuild canonical OLean objects; Lake may refresh a
`.olean.hash` sidecar while rehashing. For `formal/lean/` sources, the recorded
trace may use either the exact current formal/crypto Lake path or the exact
standalone formal/lean path; all other ordered paths are rejected, and the
official target check is still required. The builder holds a nonblocking,
process-owned exclusive lock under `formal/rp05/build/` for its full run, so a
second builder refuses instead of concurrently overwriting package state.

For an already checked retained receipt, the package reuses its original
recorded argv and provenance when it has `-j1`, `-DwarningAsError=true`,
`-DautoImplicit=false`, one positive heartbeat limit, a memory limit at or
below 16 GiB, and exact source/import/compiler/output and unchanged input pins.
It does not retroactively require `-DElab.async=false` from older receipts;
that option remains part of the flags for newly compiled package objects. An
exact valid receipt is considered before a relocated package-local cache
object, then copied and hash-verified before its provenance is written to
state.

The first build on a fresh machine compiles the package source closure and can
take substantial time. Subsequent builds reuse only OLean files whose source,
direct imported OLean hashes, and Lean version still match the recorded state;
an old retained object by itself never certifies a new package path. Generated
build output and its state live under `formal/rp05/build/`, separate from the
checked-in source snapshot.

## Updating a staged source pin

The one-time source refresh command is for a repository checkout that contains
the retained `.agent/prod-closure-2026-09-19` sources and the original source
allowlist. It checks the four allowlisted endpoint hashes and the separately
reviewed current Scheduler, ActualPivot, and shared transport hashes, follows
the four public wrappers' imports, and replaces only `formal/rp05/generated/Sources/`
and `source-manifest.json` with the resulting snapshot.

    python3 scripts/rp05_proof_package.py stage
    python3 scripts/rp05_proof_package.py inspect
    python3 scripts/rp05_proof_package.py check-source

Review the resulting generated-source and manifest diff before building. A
fresh checkout does not need `.agent` files to run `inspect`, `check-source`,
`build`, or `check`; it uses the checked-in generated source snapshot.

## Validation and execution plan

The package tests exercise reachable-source selection, external-import
boundaries, dependency order, cycle rejection, cache invalidation, strict
retained-receipt checks, Lake trace provenance, and rejection of a second
concurrent builder. All 16 tests pass.

The initial October 1 validation passed `build` and the subsequent read-only `check`
with Lean 4.32.2: 1,467 project modules, 108 external imports, and all four
public roots. The build compiled 482 modules and reused 985; it took
35 minutes 37.503 seconds. The read-only check passed in 8.555 seconds and
confirmed the exact 1,467-object tree, with no unmanifested temporary OLeans.
These results include validated reuse, not a claim of a cold compile on a
fresh machine. The successful log is retained at
`.agent/rp05-streamlining-2026-10-01/validation/package-final-frozen-validation.log`.

The updated public-ZK and single-spend package has 1,471 project modules and
the same 108 external imports. Its initial incremental build compiled five
modules and reused 1,466. A final package-only body audit then exposed a
two cached dependency variants referring to a missing internal matcher.
Recompiling those unchanged owners against the package imports and rebuilding
only affected importers compiled 18 and then 22 modules, reusing 1,453 and
1,449 respectively. The final read-only package check passes across all 1,471
modules and all four roots. All four final public-root proof-body audits also
pass with stable input fingerprints, only the standard Lean axioms, and no
missing constants or theorem bodies. The privacy audit includes the new
public-simulator result, witness independence and numerical specializations;
authorization includes the all-active classification. These are validated
local incremental builds, not a cold-build claim. Exact results are recorded
in the public evidence summary linked below.

The public claim boundaries and review decisions are recorded in
[`RP05_INDEPENDENT_REVIEW_RESOLUTIONS.md`](../../docs/crypto/RP05_INDEPENDENT_REVIEW_RESOLUTIONS.md),
with clean-check commands in
[`RP05_REVIEW_REPRODUCTION.md`](../../docs/crypto/RP05_REVIEW_REPRODUCTION.md).
Local execution plans and raw compiler/lifecycle records are not part of the
portable public review package.
