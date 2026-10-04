# Retired RISC Zero Bridge Experiment

The RISC Zero Hegemon-to-Hegemon bridge prover and guest were retired before
production. Their dependency graph included classical curve code and Plonky3,
while release Hegemon nodes require a post-quantum-only executable graph.

Release nodes still retain the versioned `RiscZeroBridgeReceiptV1` wire decoder,
message-binding prechecks, and fail-closed rejection path so historical or
malicious envelopes cannot bypass bridge policy. Lean
`Hegemon.Native.Risc0ReleaseVerifier.release_build_never_accepts` and the
generated production vectors pin that behavior. No RISC Zero receipt can stage
an inbound bridge action.

The retired experiment measured:

| Object | Bytes or time |
| --- | ---: |
| Hegemon long-range proof input | 9,951 bytes |
| Authenticated journal | 436 bytes |
| RISC Zero succinct envelope | 224,508 bytes |
| RISC Zero composite envelope | 492,158 bytes |
| Cached succinct proving | 10m46s |
| Cached composite proving | 8m37s |

Those results are historical negative evidence, not an enabled runbook or a
supported build target. A future bridge must reuse the independently tested
`consensus-light-client` statement through a post-quantum verifier whose source
and dependency graph pass the normal Hegemon release gates.
