# M4 verifier-owned public-message elision

This measured follow-up removes two redundant proof messages from the exact full Pay1x2 M4 path: the public-segment multilinear evaluation and the fixed wiring evaluation. The verifier already owns the complete 478-byte statement and fixed constraint system, so it computes both values from the same transcript challenges. Witness-dependent evaluations, reductions, commitments, and openings remain unchanged.

Apply `codex-main-public-elision-v1.patch` after the cumulative selected-wire patch at pinned Binius revision `3f96163049f680b2909f6545690bd929f1b48c44`. Build `../m4-full-pay1x2-prototype` against that exact patched checkout; the measurement manifest rewrites dependency locators only, and its source and lock hashes are recorded separately in the report. The exact rate-3 proof is **71,280 bytes**, or **71,292 bytes** with the 12-byte envelope. That saves 1,600 bytes from the preceding 72,880-byte M4 proof and 172,960 bytes (70.8156%) from the 244,240-byte selected-wire frontier.

Evidence is in `full-pay1x2-main-public-elision-2026-08-21.json`. The proof file was 71,280 bytes with SHA-256 `2e53ad3b62be531edc66bb5f1f3424d692c42c826c6f3ec002971811d5d8f8f0`. Upstream M4 composite tests, an independent direct-public-MLE differential test, all four full-relation tests, clippy with warnings denied, honest verification, public mutation, proof mutation, and exact trailing-byte rejection passed. The patch also contains two semantics-neutral cleanup changes required for the cumulative selected-wire tree to pass that clippy gate.

This is a proof-size result under the existing transparent upstream profile. It is not zero knowledge, not strict PQ128, not formally refined, and not production-authorized.
