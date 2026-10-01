import SmzaRp05PairedDagEdgeSupport

/-! Bounded finite edge-check block group for the exact paired DAG. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeChunk02

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_block_640_checked :
    (List.range 128).all (fun i => directedEdgeCheck (640 + i)) = true := by
  decide

theorem edge_block_640 (node : Nat) (lower : 640 ≤ node)
    (upper : node < 768) : directedEdgeCheck node = true :=
  block_sound 640 128 node edge_block_640_checked lower upper

private theorem edge_block_768_checked :
    (List.range 128).all (fun i => directedEdgeCheck (768 + i)) = true := by
  decide

theorem edge_block_768 (node : Nat) (lower : 768 ≤ node)
    (upper : node < 896) : directedEdgeCheck node = true :=
  block_sound 768 128 node edge_block_768_checked lower upper

private theorem edge_block_896_checked :
    (List.range 104).all (fun i => directedEdgeCheck (896 + i)) = true := by
  decide

theorem edge_block_896 (node : Nat) (lower : 896 ≤ node)
    (upper : node < 1000) : directedEdgeCheck node = true :=
  block_sound 896 104 node edge_block_896_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeChunk02
