# Maximum M4 relation geometry

Status: source-bound static audit; no circuit compile, Cargo build, prover, or
oracle allocation was performed.

Run the allocation-free counter:

    PYTHONDONTWRITEBYTECODE=1 python3 \
      .agent/hardening/binius-pq128-proof-size/max-relation-geometry/static_geometry.py \
      --pretty

The script refuses source drift. It pins the maximum-production M4 source, the
upstream Keccak implementation and compiler passes, the upstream Keccak
snapshot, the M4 commitment layout, and both PCS screens.

## Result

The fixed relation declares 114 verifier-owned in/out words and 671 private
witness words. Its universal schedule contains 83 Keccak-f permutations. The
pinned Keccak source emits exactly 600 native 64-bit FAX/AND constraints per
full permutation, or 49,800 source FAX constraints and 3,187,200 bit-level
ANDs for the complete schedule.

Backward lane liveness gives the sharper syntactic count:

- 71 final seven-lane permutations at 582 live FAX gates each;
- 4 final fourteen-lane permutations at 589 each;
- 8 intermediate full-state permutations at 600 each;
- total: 48,478 live FAX gates.

The independent non-Keccak source mirror counts 16,576 attempted internal
outputs. Starting from the deliberately conservative 49,800 full Keccak FAX
count gives 67,161 hidden words before immediate identities. Only three
incontrovertible builder-time reductions are needed: 475 constant-source
FrameBuilder BAND folds, 89 initial zero XOR folds in byte packing, and 1,261
initial zero XOR folds at sponge absorption. The resulting conservative upper
bound is 65,336 words, 200 below the `2^16` word boundary.

The guarded lower discounts one complete 25-FAX round from every permutation
for uncompiled CSE uncertainty and is 47,188 words. Packing two words per B128
symbol therefore gives the source-static interval:

    hidden words:       47,188 .. 65,336
    active B128 symbols:23,594 .. 32,668
    n15 random tail:       100 ..  9,174 symbols

Thus the likely padded relation is n15: `2^16` committed words become `2^15`
B128 symbols. The margin is narrow. This is not a compiled statistic or a
formal bound because the upper relies on the pinned fusion invariant that
Keccak linear definitions remain scratch/inlined. The pinned 1-KiB Keccak
snapshot supports that invariant exactly: eight permutations produce 4,779
AND constraints and 4,779 committed internal words, matching seven full
permutations plus a four-lane final permutation (`7*600 + 579`). A compile is
still mandatory to freeze `n_hidden_words`, constraint counts, exact active
symbols, and exact random-tail slack.

## PCS consequence

At n15, the strict refold screen is 117,488 raw bytes and 117,500 envelope
bytes, 6,580 bytes under the raw cap, but its encoded oracle is 32 GiB. It is
not runnable under the current 28-GiB disk gate and has no complete-ZK or
strict-security admission. If the compile crosses into n16, the same screen is
144,496 raw bytes, 20,428 bytes over the cap, with a 64-GiB oracle.

The independent binding-vector screen remains 288,408 raw bytes at n15 with a
24-GiB oracle. Its tier price is unchanged across the active-symbol interval,
and its nonlinear masked-M4 grammar is unimplemented. Neither screen is a
frontier point or a strict/formal security result.
