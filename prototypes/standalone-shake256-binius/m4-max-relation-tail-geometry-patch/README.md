# Maximum-M4 random-tail geometry patch

Status: applied source-static optimization. The live maximum-relation prototype
contains this rewrite followed by the Merkle-selector, one-hot mux, and policy
deduplication rewrites and hashes to
`f8ac13bdd657b47d614d8a7b65524ddb21498efcedf0e9888d0951d7fa851d6b`.
No circuit was compiled, no Cargo command was run, and no proof or encoded
oracle was allocated.

This patch preserves the 83-Keccak scalar relation while making three already
equivalent computations explicit in the source:

1. The 853-byte public statement is decoded directly from its 107 packed
   little-endian public words. It no longer extracts every byte and then packs
   the same bytes back into words. Exact magic, version, and activation bytes
   are enforced by full- or masked-word equalities.
2. Each Merkle left/right swap computes `mask & (current ^ sibling)` once and
   reuses it for both children.
3. Balance constraints reuse the numeric note value and selector words already
   produced by note validation instead of byte-swapping them again.

The preserved patch applies forward only to the former source whose SHA-256 is
`67e7f6ac6a15579043de5a9a0565b374667b094890bbf31053a818479697ed91`.
The checker stages the live source in a unique temporary directory, reverses
the three later patches to recover the exact intermediate hash, then reverses
this patch to recover the exact base hash. This proves the checked-in four-patch
chain without editing the live tree; the temporary directory is automatically
removed.

Run the allocation-free certificate from the repository root:

    PYTHONDONTWRITEBYTECODE=1 python3 \
      prototypes/standalone-shake256-binius/m4-max-relation-tail-geometry-patch/check_tail_geometry_patch.py \
      --pretty

Expected source-static result:

    conservative hidden-word upper: 65,336 -> 61,469
    guaranteed hidden-word cut:                 3,867
    active B128 symbol upper:                  30,735
    guaranteed n15 random-tail lower:           2,033
    conditional 1,060-symbol margin:              973
    full 1,984-symbol margin:                       49

The checker pins the applied maximum source, scalar relation, action adapter,
composed-envelope boundary, and relevant upstream builder, zero-fold, CSE,
fusion, byte-swap, and Keccak files. It verifies the frozen patch in reverse,
runs 72,636 deterministic scalar-equivalence checks, and recomputes the exact
source-operation accounting. The patch itself is
`hegemon-m4-max-tail-geometry-67e7f6ac.patch`.

The 3,867-word figure is a tightening of the conservative syntactic upper, not
a compiled-size claim. The pinned compiler already enables CSE, so it may have
removed the repeated Merkle deltas and byte swaps from the old graph. Only a
disk-admitted compile can establish the actual constraint and proof-byte delta.

The 49-symbol full-profile margin is deliberately reported as narrow. A real
FRI/proximity construction may need more padding observations, and only a
disk-admitted circuit compile can freeze the actual hidden-word count. This is
not compiled evidence, a proof-size measurement, complete zero knowledge,
strict PQ128/QROM security, or a frontier point.
