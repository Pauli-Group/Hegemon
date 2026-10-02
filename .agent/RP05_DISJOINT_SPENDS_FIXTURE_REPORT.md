# RP05 same-parent disjoint-spend fixtures

Prepared helper: `circuits/transaction/examples/rp05_smza_disjoint_spends_artifact.rs`.
The coordinator owns the build/prover lane. No generated proof or accepted
multi-proof block is claimed until the commands below succeed.

## Exact fixture construction

The helper imports the source-owned repaired positive fixture and its freshly
encoded action-11 coinbases. Its PUBLIC test wallet seed is `[0x51; 32]`,
diversifier 9. Both original coinbase notes have positive native value and
occupy canonical positions 0 and 1 in the same two-note tree at parent height 2.
The source fixture binds the full current single-key authorization digest,
not the historical retained note randomness.

`spend-note0` uses original input 0 and original output 0; `spend-note1` uses
original input 1 and original output 1. Each is mapped into active slot 0;
input/output slot 1 is canonical zero. Both preserve the original note opening,
spend key, Merkle position/path, positive value and authenticated v5 output
ciphertext. The helper recomputes the executable source hash schedule and
requires its root, nullifier and output commitment to equal the corresponding
original values. It validates the complete witness and ciphertext surface and
checks the lowered packed witness before proving.

Each proof uses the unchanged HGV8RP05 relation digest and SMZA profile 9 /
domain set 5 / source network ID. Both statements carry parent height 2 and
disabled stablecoin root `[0; 7]`. Their active nullifiers and output commitments
must be different. Outputs are actual source-fixture outputs, not freshly
wallet-generated outputs; the manifest says this explicitly.

## Artifact contract

Create-only output under `.agent/artifacts/smallwood-poseidon2-v8-smza` contains:

- `manifest.json`, `readback.json`, `relation-program.bin`;
- exact `coinbase-height1.bin` and `coinbase-height2.bin` for state seeding;
- each role's `proof.bin`, `native-leaf.bin`, `rpc-envelope.bin`, `inline-args.bin`,
  `public-inputs.bin`, `kernel-binding.bin` and transcript `context.bin`.

Schema: `hegemon-smallwood-poseidon2-v8-smza-disjoint-spends-v1`.
The manifest pins the current full proof source inventory, unchanged relation
program, helper source, shared fixture source, actual generator executable,
all carrier bytes/hashes, exact per-role fixture descriptors and independent
proof randomness. Generation and verification reject any source/generator
change during their run. Executable identities remain informational generation
metadata, not universal compiler-refinement evidence or release authority.

`verify` rebuilds both source fixtures, requires their exact public values and
relation bindings, source-verifies the retained proofs, reconstructs all
carriers and compares every retained byte/descriptor. It requires distinct
proofs, wire salts and DECS roots. Both production flags remain false.

## Reproduction after coordinator lane grant

From `/private/tmp/hegemon-verifier-20261002`, with the coordinated compatible
target directory and a stable source tree:

    cargo build --locked --offline --profile retained-proof -p transaction-circuit --features rp05-dev-artifacts --example rp05_smza_disjoint_spends_artifact
    RAYON_NUM_THREADS=2 TARGET/retained-proof/examples/rp05_smza_disjoint_spends_artifact generate .agent/artifacts/smallwood-poseidon2-v8-smza/disjoint-parent2
    RAYON_NUM_THREADS=2 TARGET/retained-proof/examples/rp05_smza_disjoint_spends_artifact verify .agent/artifacts/smallwood-poseidon2-v8-smza/disjoint-parent2

The two prover invocations are sequential in one process. Keep the aggregate
coordinator memory budget of 16 GiB and no concurrent heavy build/prover lane.
The earlier two-input proving time is only an estimate for this run; exact
per-proof generation seconds are recorded in the new manifest.

## Acceptance handoff

The verifier worker owns actual connector admission of both exact native leaves
in one valid block, canonical action order, exact leaf retention and durable
typed state/root/nullifier equality after close/reopen. Existing malformed
proof, double-spend and error-order regressions remain in force. This helper
does not establish those node checks by itself.

Current local checks: Rust formatting and `git diff --check` passed. Build,
proof generation, source readback and valid-block acceptance are pending.
