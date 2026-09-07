# Proof-campaign disk maintenance, 2026-09-07

The user explicitly directed the coordinator to manage disk space and keep
producing the proofs. The prior 40 GiB cutoff was coordinator-invented and is
removed. Warm Lean checks continue independently of this narrow maintenance.

Selected disposable outputs, after read-only inspection:

- `/Users/pldd/Projects/Reflexivity/Hegemon/target/debug/incremental`:
  Cargo incremental compiler cache; approximately 301,387,776 exclusive inode
  bytes before APFS sharing. No source, proof artifacts, or node/wallet state.
- `/Users/pldd/Projects/Reflexivity/Hegemon/scripts/hegemon_formal_core/target/debug/incremental`:
  Cargo incremental compiler cache; approximately 298,631,168 exclusive inode
  bytes before APFS sharing.

Both exact directories are ignored build outputs, are not symlinks and contain
compiler dependency graphs, metadata, work-product indexes and object files.
Elevated process/open-file inspection found no Cargo/rustc process or open
file in the selected cache trees. Searches of retained manifest, campaign,
configuration, output and audit scopes found no exact-path artifact reference.

Only these two incremental directories are removed. Dependency outputs,
executables, Cargo.lock, source, warm Lean/mathlib caches, retained proofs,
benchmark artifacts, wallet/node data and unrelated work remain untouched.
The deleted cache bytes are not archived; Cargo regenerates them on subsequent
builds from the preserved source/toolchain. No proof regeneration is required.

Rebuild if needed with the original Cargo build/test command. The formal-core
checker uses `cargo build --locked --manifest-path scripts/hegemon_formal_core/Cargo.toml`.
This maintenance does not justify a security claim or change any proof gate.
