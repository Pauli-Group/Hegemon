# M4 random-tail integration report

## Verdict

The pinned source can support a narrow random-tail integration without changing the verifier: preserve the exact declared private-word prefix, keep an odd final word's B128 partner zero, fill every later whole B128 symbol through the n15 boundary from a cryptographic RNG, and feed the identical resulting word buffer to both the shift reduction and trace commitment. The isolated five-file delta and static checker implement and ratchet that seam after the coefficient/grouped prerequisite stack.

This is source-static evidence only. The exact active-prefix count is now exported by the runtime API, but the maximum relation was not compiled and no count is reported. The complete clear-observation matrix cannot be exported through current APIs, so ZK, strict security, proof bytes, and frontier eligibility remain false.

## Frozen stack and delta

```text
base Binius revision  3f96163049f680b2909f6545690bd929f1b48c44
coefficient patch     684ad2cde0d49fcb095fd542990dd3dcfa246d7a0378b7ec8f7377fcfa9d2c54
grouped patch         37dfdee589e476c09fe5c955bd46942cd5aa293a3177d7a43d07f14aeb8ef9df
random-tail patch     0602c48f3cc7545186e625d033c3cefe4563431499977531e365144d12232c18
random-tail bytes     15300
changed files         5
verifier files        0
maximum source files  0
```

The separately optimized maximum sources hash to `f8ac13bdd657b47d614d8a7b65524ddb21498efcedf0e9888d0951d7fa851d6b` (`src/lib.rs`) and `d1ad66f1d5d3203bbc716b2c88157153eb42a06fde95a9df8eaad187e96a454c` (`src/main.rs`). The random-tail delta itself still changes zero maximum-source files.

## Integration mechanics

`crates/prover/src/prove.rs` adds a shared prover body whose `trace_words` parameter is used by both `pack_witness` and `prove_shift_reduction`. The ordinary path passes the original private slice, preserving existing behavior. The new path first calls `random_trace_tail_geometry`, copies the active words, appends one zero word if needed to finish a partially active B128 symbol, and appends two little-endian words for each fresh `u128` RNG draw.

The geometry gate checks exact witness/key private-word counts, full n16 shift-word dimension for the n15 symbol trace, and at least one complete unused B128 symbol. The returned geometry exposes all counts needed to replace the prior source-only active-length assumption after the maximum circuit can be compiled.

`crates/m4-prover/src/composite.rs` adds the one-main entry point. It rejects numbered chips, witness tables, IntMul, any oracle count other than one, any tier other than n15, a mismatch between main and compiler dimensions, and an already-masked oracle. Preflight completes before transcript channel creation.

## Relation exclusion anchors

The active relation cannot name the tail because constraint validation rejects indices at or above each declared segment length. Shift phase 1 truncates at `segment.key_ranges`; the monster polynomial emits `segment.n_words()` entries then zero-fills its remaining word domain; phase 2 multiplies the trace by that monster; and the verifier wiring evaluator slices its hidden tensor at `cs.n_private`. The patch does not change these sources. The checker pins their hashes and verifies the relevant expressions.

## Required observation rows and blocker

Random padding hides only if the padding columns span every clear witness-dependent observation in the realized transcript. The required union includes, at minimum:

1. every coefficient of every phase-2 shift sumcheck round polynomial plus its final `witness_eval`;
2. all 128 ring-switch `s_hat_v` coordinates;
3. every trace-dependent BaseFold Phase-A sumcheck message and the reduced trace alpha; and
4. every codeword/coset symbol and terminal symbol sent for the actual adaptive FRI indices, expanded into B128 coordinates.

Commitment and Merkle hashes are not linear rows, but they make the Fiat--Shamir schedule padding-dependent and therefore require a separate adaptive BCS/ROM simulator argument.

Pinned `IPProverChannel` exposes only `send_one(elem)` and `send_many(elems)`. By that boundary, the exact coefficient rows and their challenge provenance have been erased. A logging wrapper would record values, not functionals, and cannot feed the rank audit. The minimal sound interface is a `LinearObservationSink` emitted from the protocol implementations themselves, after actual challenges/indices are fixed, with `(oracle_id, phase, kind, B128_row, observed_value, challenge_provenance)`. A verifier/replay counterpart must bind or rederive the same schedule. Until that exists, `complete_linear_observation_union_exported` is false.

## Validation

The three ordered patches apply cleanly. The source checker passes against the reconstructed post-stack tree, pinning 20 source files and confirming the five-file scope, unchanged verifier, separately pinned maximum source, exact RNG range, odd-symbol handling, shared buffer, admission order, selector exclusions, observation anchors, and algebra KATs. Direct rustfmt and `git diff --check` pass. Rustfmt reports only that the repository's nightly-only formatting options are unavailable on the installed stable formatter.

Free disk was approximately `25,016,296 KiB`, below the `29,360,128 KiB` admission threshold. No Cargo command, dependency resolution, compilation, test binary, prover, verifier, or proof measurement ran.

## Authority state

```text
source_static_pass = true
active_prefix_exported = true
maximum_active_prefix_measured = false
selector_tail_zero_source_static = true
complete_linear_observation_union_exported = false
compiled = false
roundtrip = false
adaptive_BCS_ZK = false
strict_SHAKE256_512_integrated = false
strict_security = false
proof_bytes = null
frontier_eligible = false
```

Downstream strict PCS commitments must use SHAKE256-512 with a 64-byte digest. The present delta is hash-agnostic and cannot be cited for that integration or for any prior compact wire estimate.
