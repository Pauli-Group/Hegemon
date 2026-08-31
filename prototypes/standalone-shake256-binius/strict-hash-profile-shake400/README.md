# Isolated SHAKE256-400 proof-hash profile

This frozen research crate supplies 50-byte SHAKE256 proof-hash plumbing for the measured
maximum-M4 prototype. It is deliberately separate from the repository's retained 64-byte
SHAKE256-512 profile.

It implements independently domain-separated Merkle leaves, Merkle nodes, and Fiat-Shamir
transcripts; a Binius-compatible `HashSuite`; and a canonical pre-statement context binding the
pinned backend, circuit, relation, hash profile, challenge-field encoding, source bundle, and
inverse rate. Tests include independent Python `hashlib` vectors for the 50-byte digest and the
challenger's cross-digest rollover, reset/domain separation, sequential-versus-parallel leaf
hashing, ordered node compression, exact transcript exhaustion, and wrong-context rejection.

The measured artifact repeats the patched full-maximum M4 proof three times and passes the
implemented arithmetic screen. This remains a prototype result. The active per-copy challenge
field is B128, upstream's 96-bit constant covers only its FRI query phase, and no reviewed
direct-product/QROM theorem promotes three transcripts to a composed PQ128 guarantee. It is not
production or formal authorization, and it does not replace the SHAKE256-512 release policy.
