import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 7578 through 7593. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7482Part06

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_7578_checked :
    (List.range 16).all (fun i => directedEdgeCheck (7578 + i)) = true := by
  decide

theorem edge_subblock_7578 (node : Nat) (lower : 7578 ≤ node)
    (upper : node < 7594) : directedEdgeCheck node = true :=
  block_sound 7578 16 node edge_part_7578_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7482Part06
