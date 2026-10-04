# HX512 formal/refinement checkpoint

This checkpoint is structural and inactive. It pins the independently replayed
HX512 transcript primitive and the Lean codec/state-machine model while keeping
the live engine source, exact final geometry, protocol identity, Rust codec
conformance, SHA-512 request framing, SHAKE256 sampler refinement, compiled
relation refinement, and production authority explicitly absent.

The q48/s6/eta5 constants are not a soundness profile. SmallWood Theorem 1 /
Equation 14 retains the high-degree codeword-weight term; the repository has
not justified replacing that term with a bare `p^-eta` contribution.

Run the source-only inactive integrity gate with:

    python3 -B .agent/hardening/hx512-formal-refinement/check_refinement.py --json

Run its adversarial tests with:

    python3 -B .agent/hardening/hx512-formal-refinement/test_refinement.py

The production-form check is deliberately negative until every blocker is
replaced by independently replayable evidence:

    python3 -B .agent/hardening/hx512-formal-refinement/check_refinement.py --require-qualified

The full Lean build and axiom audit are deferred by the repository disk gate.
When admission reopens, run:

    cd formal/crypto
    lake build HegemonCrypto
    lake env lean --run ../../scripts/lean_axiom_audit.lean credited-declarations.txt HegemonCrypto

Those commands check elaboration and the axiom allowlist; they still do not
establish concrete-hash QROM security, complete zero knowledge, Rust/compiler
refinement, or consensus/restart/reorg binding.
