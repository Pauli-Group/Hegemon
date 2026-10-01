import SmzaRp05PairedDagEdgeSupport

/-! Bounded finite edge-check block group for the exact paired DAG. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeChunk01

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_block_128_checked :
    (List.range 128).all (fun i => directedEdgeCheck (128 + i)) = true := by
  decide

theorem edge_block_128 (node : Nat) (lower : 128 ≤ node)
    (upper : node < 256) : directedEdgeCheck node = true :=
  block_sound 128 128 node edge_block_128_checked lower upper

private theorem edge_block_256_checked :
    (List.range 128).all (fun i => directedEdgeCheck (256 + i)) = true := by
  decide

theorem edge_block_256 (node : Nat) (lower : 256 ≤ node)
    (upper : node < 384) : directedEdgeCheck node = true :=
  block_sound 256 128 node edge_block_256_checked lower upper

private theorem edge_block_384_checked :
    (List.range 128).all (fun i => directedEdgeCheck (384 + i)) = true := by
  decide

theorem edge_block_384 (node : Nat) (lower : 384 ≤ node)
    (upper : node < 512) : directedEdgeCheck node = true :=
  block_sound 384 128 node edge_block_384_checked lower upper

private theorem edge_block_512_checked :
    (List.range 128).all (fun i => directedEdgeCheck (512 + i)) = true := by
  decide

theorem edge_block_512 (node : Nat) (lower : 512 ≤ node)
    (upper : node < 640) : directedEdgeCheck node = true :=
  block_sound 512 128 node edge_block_512_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeChunk01
