import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 4106 through 4121. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4026Part05

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_4106_checked :
    (List.range 16).all (fun i => directedEdgeCheck (4106 + i)) = true := by
  decide

theorem edge_subblock_4106 (node : Nat) (lower : 4106 ≤ node)
    (upper : node < 4122) : directedEdgeCheck node = true :=
  block_sound 4106 16 node edge_part_4106_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4026Part05
