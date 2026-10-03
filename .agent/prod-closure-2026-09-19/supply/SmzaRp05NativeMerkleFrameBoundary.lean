import SmzaRp05NativeFrontierModel

/-!
# Native note-tree compression frame boundary

`Poseidon2V8NoteTreeState::append` calls `compress_note_roots`, which converts
two validated seven-limb digests to Goldilocks felts and calls
`poseidon2_width16_compress14(MERKLE_DOMAIN_TAG, ...)`. The source compressor
uses `left[0..7] || right[0..7] || domain || suite`, then one width-16
permutation and the first seven output lanes. This file proves the exact
*frame* used by the Lean frontier hash; it does not postulate that compiled
Rust `Felt` permutation execution equals the Lean permutation.

The remaining implementation obligation is confined to canonical-limb
conversion, the width-16 permutation on this frame, and canonical output
conversion. The source-owned default leaf's note sponge has a separate
primitive-equivalence obligation. No proof or consensus bytes change.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05NativeMerkleFrameBoundary

open Hegemon.Transaction.Poseidon2V8SemanticSpecification

set_option autoImplicit false

/-- The literal 16-lane source layout used at every native Merkle level.
The seven `getD` accesses correspond to the validated Rust `[u64; 7]`
members; exact length and canonicality are obligations of the decoder or
constructor when relating a concrete Rust state to this list model. -/
def nativeMerkleFrame (left right : Digest) : List Nat :=
  [left.getD 0 0, left.getD 1 0, left.getD 2 0,
   left.getD 3 0, left.getD 4 0, left.getD 5 0,
   left.getD 6 0, right.getD 0 0, right.getD 1 0,
   right.getD 2 0, right.getD 3 0, right.getD 4 0,
   right.getD 5 0, right.getD 6 0,
   poseidon2V8MerkleDomain, poseidon2V8SuiteMarker]

theorem native_merkle_frame_width (left right : Digest) :
    (nativeMerkleFrame left right).length =
      Hegemon.Transaction.Poseidon2Width16Kernel.width := by
  rfl

/-- The Lean compress14 initializer is exactly the native source's lane
layout, with domain 4 and the fixed `HEG_P216` suite marker. -/
theorem lean_merkle_initializer_is_native_frame (left right : Digest) :
    ((List.range Hegemon.Transaction.Poseidon2Width16Kernel.width).map fun lane =>
      if lane < digestWords then left.getD lane 0
      else if lane < 2 * digestWords then right.getD (lane - digestWords) 0
      else if lane = 2 * digestWords then poseidon2V8MerkleDomain
      else poseidon2V8SuiteMarker) = nativeMerkleFrame left right := by
  rfl

/-- The exact mathematical seam left after fixing the source frame: only
the first seven lanes of the one permutation are observed as a note root. -/
theorem lean_merkle_compress_is_native_frame_permutation
    (left right : Digest) :
    poseidon2V8Compress14 poseidon2V8MerkleDomain left right =
      (Hegemon.Transaction.Poseidon2Width16Kernel.permutation
        (nativeMerkleFrame left right)).take digestWords := by
  rw [poseidon2V8Compress14, lean_merkle_initializer_is_native_frame]

end HegemonCrypto.SmallWood.SmzaRp05NativeMerkleFrameBoundary
