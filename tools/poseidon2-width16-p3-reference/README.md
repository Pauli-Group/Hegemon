# Poseidon2 width-16 p3 reference

This evidence-only crate instantiates `p3-poseidon2 0.6.3` with Hegemon's
2026/306-hardened external layer, original Horizen internal diagonal, and
canonical width-16 Grain constants. It compares the permutation, fixed
compression, and all sponge KAT lengths against `transaction-core`. It also
requires the stock p3 width-16 permutation to differ, because stock p3 uses the
opposite Kronecker orientation and a later optimized internal diagonal.

The crate is intentionally outside Hegemon's production Cargo workspace. p3
0.6.3 does not compile under the repository's pinned Rust 1.91.1, so run the
locally installed compatible toolchain explicitly:

    cargo +1.97.1 run --locked --offline --manifest-path tools/poseidon2-width16-p3-reference/Cargo.toml

Success prints one line ending in `stock p3 negative control differs`.
