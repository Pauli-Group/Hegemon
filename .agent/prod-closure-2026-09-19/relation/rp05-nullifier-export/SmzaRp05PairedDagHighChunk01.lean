import SmzaRp05PairedDagEdgeSupport

/-! Bounded finite edge-check block group for the exact paired DAG. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighChunk01

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_block_2490_checked :
    (List.range 128).all (fun i => directedEdgeCheck (2490 + i)) = true := by
  decide

theorem edge_block_2490 (node : Nat) (lower : 2490 ≤ node)
    (upper : node < 2618) : directedEdgeCheck node = true :=
  block_sound 2490 128 node edge_block_2490_checked lower upper

private theorem edge_block_2618_checked :
    (List.range 128).all (fun i => directedEdgeCheck (2618 + i)) = true := by
  decide

theorem edge_block_2618 (node : Nat) (lower : 2618 ≤ node)
    (upper : node < 2746) : directedEdgeCheck node = true :=
  block_sound 2618 128 node edge_block_2618_checked lower upper

private theorem edge_block_2746_checked :
    (List.range 128).all (fun i => directedEdgeCheck (2746 + i)) = true := by
  decide

theorem edge_block_2746 (node : Nat) (lower : 2746 ≤ node)
    (upper : node < 2874) : directedEdgeCheck node = true :=
  block_sound 2746 128 node edge_block_2746_checked lower upper

private theorem edge_block_2874_checked :
    (List.range 128).all (fun i => directedEdgeCheck (2874 + i)) = true := by
  decide

theorem edge_block_2874 (node : Nat) (lower : 2874 ≤ node)
    (upper : node < 3002) : directedEdgeCheck node = true :=
  block_sound 2874 128 node edge_block_2874_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighChunk01
