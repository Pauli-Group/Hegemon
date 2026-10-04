# Selected implementation path: standalone SHAKE256 proof

Each wallet transaction carries one canonical binary-native zero-knowledge proof. The same bytes are verified before relay, included in the block, and reverified during sync, reorg, and fresh replay.

The transaction relation uses fixed-layout SHAKE256-448 semantic hashes. Proof commitments and Fiat-Shamir use SHAKE256-512. The implementation begins from the direct IronSpartan path in an isolated Binius64 fork, replaces its insufficient 96-bit/SHA-256/GF(2^128) profile, proves end-to-end zero knowledge, removes the 6,080-byte Hegemon outer artifact, and measures the exact maximum-shape result before activation.

The parser hard cap is 1 MiB and the optimization target is 512 KiB. At the current 64 MiB block cap this permits at most 63 or 126 maximum-sized transfers respectively. The previous 520-transfer target reopens only after a measured standalone artifact reaches 124,080 bytes; proof aggregation, sidecars, larger blocks, and builder-held witnesses are not substitutes.

See `.agent/STANDALONE_SHAKE256_BINARY_PROOF_EXECPLAN.md` for implementation and release gates.
