import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 3258 through 3273. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3258Part00

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_3258_checked :
    (List.range 16).all (fun i => directedEdgeCheck (3258 + i)) = true := by
  decide

theorem edge_subblock_3258 (node : Nat) (lower : 3258 ≤ node)
    (upper : node < 3274) : directedEdgeCheck node = true :=
  block_sound 3258 16 node edge_part_3258_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3258Part00
