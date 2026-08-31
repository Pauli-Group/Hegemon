# Hegemon dependency patch

This directory vendors `reed-solomon-erasure` 6.0.0 from crates.io, preserving
its MIT license and implementation. The original crates.io archive checksum is
`7263373d500d4d4f505d43a2a662d475a894aa94503a1ee28e9188b5f3960d4f`.
Hegemon's only source delta updates the internal decode-matrix cache from `lru`
0.7.8 to exactly 0.18.2 and passes the same non-zero capacity through the newer
constructor API. The erasure-code matrix, encode, verify, and reconstruction
algorithms are unchanged.

The patch removes the dependency affected by RUSTSEC-2026-0253. Exact parity
bytes and reconstruction behavior are pinned by the owning `state-da` tests.
