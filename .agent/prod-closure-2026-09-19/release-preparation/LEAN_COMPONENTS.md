# RP04/q38 checked mathematical components

This source bundle is **not the complete production security contract**.
The manifest selects previously checked component roots and their recursive
custom-source dependencies. Unfinished drafts are excluded from its build.
The local PASS receipts establish component checks, not the global q38 count,
full adaptive privacy, or production authorization.

The current manifest contains 31 checked roots and 23 recursive dependencies.
The added `SmzaPhysicalStageRecord` root proves physical Record/Split kernel
conjugation and operator intertwining. Accepted readout and common-execution
identification remain separate open obligations.

Validate the packaged source hashes and recursive custom imports, without
invoking a compiler:

```sh
python3 scripts/check_smza_lean_components.py --check-sources
```

To reproduce component checks, first prepare the repository's pinned Lean
toolchain and existing `formal/lean` and `formal/crypto` Lake dependencies.
Use the toolchain specified by `formal/crypto/lean-toolchain`. Then explicitly
select a fresh output directory and invoke:

```sh
python3 scripts/check_smza_lean_components.py --compile \
  --output-dir /absolute/path/to/fresh-component-output
```

The helper checks source hashes before compiling in dependency order, serially,
with `-j1 -M2800`, warnings as errors and implicit variables disabled. It places
new component objects before external Lake libraries in the import path. It
does not install dependencies, download artifacts, run a native prover, or
activate production. It does not impose a whole-process memory or scratch cap;
the active local compiler lane additionally uses its retained bounded runner.
No fresh all-component rebuild is claimed solely from a source-manifest pass.

The new counting route uses the degree-405 truncated Newton response directly:
either one affine pair covers every specialization of a branch, or at most405
positions have identical generic incidence. This does not require that the
generic Newton residual vanish. Consequently the separate residual-exception
case can be omitted. Its proposed total is1,694,784,843,179, below the existing
12,310,499,043,179 target. The complete formal assembly of that shorter argument
remains pending. Query count, protocol degrees and serialized proof-size caps
are unchanged.
