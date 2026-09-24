# M4 padding-fiber terminal compression

This patch is applied after the selected-value, main-public-elision, and terminal-target patches. It applies a public bijection to the single unmasked M4 trace oracle so the natural zero padding occupies complete 16-element FRI fibers. The corresponding public-point permutation preserves the oracle's multilinear evaluation exactly.

The complete patch chain applies cleanly, in this order, to pinned Binius64 revision `3f96163049f680b2909f6545690bd929f1b48c44`: selected wire `fa442ca4fd18fec239e874134c4cd41d82e2caafacfe987c9ea5867ededd45ee`, main-public elision `8607f483270187ff32d2802b5a4584dd208150b31ee8c333b8201b33d9ee0d9c`, terminal-target leaves `d0bfabb7bffcab6097af635913e662506afc73d2b354382158d9350b827fcee9`, then this padding-fiber patch `b64d4f5efb13156a5d854378e2805198a185e98ffd6e13ebc0a0c1ee461bd995`.

For the full Pay1x2 trace, 12,486 B128 message elements may be nonzero. After the four initial fold variables, only `ceil(12,486 / 16) = 781` of the 1,024 terminal-message elements may be nonzero. The prover commits the full terminal vector but serializes only the 781-element prefix. The verifier restores 243 fixed zeros and authenticates the complete 1,024-element vector against the original observed Merkle root. A malicious nonzero first omitted coordinate is rejected.

Verified rate sweep:

| log inverse rate | proof bytes |
| ---: | ---: |
| 2 | 70,864 |
| 3 | 66,304 |
| **4** | **65,440** |
| 5 | 66,512 |
| 6 | 68,208 |

Selected result:

- raw proof: **65,440 bytes**
- direct envelope: **65,452 bytes**
- proof SHA-256: `028f1fadc26e167768667487717508f481c2f1d70563e51088873757f43338ec`
- patch SHA-256: `b64d4f5efb13156a5d854378e2805198a185e98ffd6e13ebc0a0c1ee461bd995`
- reduction from the preceding 69,456-byte frontier: **4,016 bytes (5.78%)**
- cumulative reduction from the 244,240-byte selected IronSpartan wire: **178,800 bytes (73.21%)**

The full 40-permutation Pay1x2 circuit, scalar/circuit differential fixtures, public/proof/trailing mutations, padding bijection, evaluation invariance, exact zero suffix, BaseFold round-trip, compact terminal round-trip, malicious omitted-coordinate rejection, natural-layout fallback, Clippy `-D warnings`, and rates 2–6 all pass.

This remains a research prototype. The pinned backend is transparent, uses the upstream 96-bit query profile, SHA-256 commitments, and GF(2^128); it is neither zero-knowledge nor strict PQ128. The compact wire is direct/native-verifier only. Recursive compact methods fail closed. Static generic proof-size accounting still overstates the compact terminal and must not be used as an exact frontier measurement.
