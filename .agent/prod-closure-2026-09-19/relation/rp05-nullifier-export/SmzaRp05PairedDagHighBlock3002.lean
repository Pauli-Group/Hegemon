import SmzaRp05PairedDagHighChunk00

/-! Exact single-block directed-edge check for current/reference DAG nodes 3002 through 3129. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3002

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

open HegemonCrypto.SmallWood.SmzaRp05PairedDagHighChunk00.FastLookup

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem fast_edge_block_3002_checked :
    (List.range 128).all (fun i => fastDirectedEdgeCheck (3002 + i)) = true := by
  decide

private theorem edge_block_3002_checked :
    (List.range 128).all (fun i => directedEdgeCheck (3002 + i)) = true := by
  exact edge_block_of_fast 3002 128 fast_edge_block_3002_checked

theorem edge_block_3002 (node : Nat) (lower : 3002 ≤ node)
    (upper : node < 3130) : directedEdgeCheck node = true :=
  block_sound 3002 128 node edge_block_3002_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3002
