# M4 terminal-target leaf elision

This patch is an additive wire optimization over the selected-value plus main-public-elision M4 prototype. For the single unlifted input oracle with no later FRI oracle, the verifier already holds the authenticated terminal-codeword value to which each 16-element input leaf folds. The prover therefore sends 15 division-free slopes per distinct leaf instead of all 16 field elements. The verifier reconstructs the full leaf, authenticates it against the unchanged Merkle root, and independently checks that it folds to the terminal target.

The transformation is bijective for every challenge, including zero and one, and performs no division. Query indices are sampled before either decommitment block; reordering the terminal and leaf advice does not change Fiat-Shamir state. The measured proof has 114 distinct queried leaves and saves exactly `114 * 16 = 1,824` bytes.

Verified result:

- raw proof: **69,456 bytes**
- direct envelope: **69,468 bytes**
- previous raw proof: 71,280 bytes
- proof SHA-256: `394bcefc53b774b31e4e4e4f9d964051590891bf3d66912226678e157915d401`
- patch SHA-256: `d0bfabb7bffcab6097af635913e662506afc73d2b354382158d9350b827fcee9`

The full 40-permutation Pay1x2 circuit, 16 scalar/circuit differential fixtures, honest proof, every public-word mutation, proof mutation, trailing-byte rejection, fold-target round-trip, duplicate-query handling, wrong-target rejection, and Clippy `-D warnings` pass.

This remains a research prototype. The pinned backend is transparent, uses the upstream 96-bit query profile, SHA-256 commitments, and GF(2^128), so it is neither zero-knowledge nor strict PQ128. The direct native verifier consumes the new wire. Recursive builder/filler channels and the pre-existing generic exact-size estimator do not yet model the compact wire and must not be treated as compatible or authoritative.
