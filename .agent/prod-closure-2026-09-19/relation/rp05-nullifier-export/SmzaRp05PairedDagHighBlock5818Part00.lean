import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 5818 through 5833. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5818Part00

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_5818_checked :
    (List.range 16).all (fun i => directedEdgeCheck (5818 + i)) = true := by
  decide

theorem edge_subblock_5818 (node : Nat) (lower : 5818 ≤ node)
    (upper : node < 5834) : directedEdgeCheck node = true :=
  block_sound 5818 16 node edge_part_5818_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5818Part00
