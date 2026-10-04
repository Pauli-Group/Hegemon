import SmzaRp05PairedDagEdgeSupport

/-! Bounded finite edge-check block group for the exact paired DAG. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighChunk00

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_block_1978_checked :
    (List.range 128).all (fun i => directedEdgeCheck (1978 + i)) = true := by
  decide

theorem edge_block_1978 (node : Nat) (lower : 1978 ≤ node)
    (upper : node < 2106) : directedEdgeCheck node = true :=
  block_sound 1978 128 node edge_block_1978_checked lower upper

private theorem edge_block_2106_checked :
    (List.range 128).all (fun i => directedEdgeCheck (2106 + i)) = true := by
  decide

theorem edge_block_2106 (node : Nat) (lower : 2106 ≤ node)
    (upper : node < 2234) : directedEdgeCheck node = true :=
  block_sound 2106 128 node edge_block_2106_checked lower upper

private theorem edge_block_2234_checked :
    (List.range 128).all (fun i => directedEdgeCheck (2234 + i)) = true := by
  decide

theorem edge_block_2234 (node : Nat) (lower : 2234 ≤ node)
    (upper : node < 2362) : directedEdgeCheck node = true :=
  block_sound 2234 128 node edge_block_2234_checked lower upper

private theorem edge_block_2362_checked :
    (List.range 128).all (fun i => directedEdgeCheck (2362 + i)) = true := by
  decide

theorem edge_block_2362 (node : Nat) (lower : 2362 ≤ node)
    (upper : node < 2490) : directedEdgeCheck node = true :=
  block_sound 2362 128 node edge_block_2362_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighChunk00
