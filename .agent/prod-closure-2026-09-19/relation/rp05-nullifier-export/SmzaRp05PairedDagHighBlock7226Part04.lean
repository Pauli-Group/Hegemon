import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 7290 through 7305. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7226Part04

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_7290_checked :
    (List.range 16).all (fun i => directedEdgeCheck (7290 + i)) = true := by
  decide

theorem edge_subblock_7290 (node : Nat) (lower : 7290 ≤ node)
    (upper : node < 7306) : directedEdgeCheck node = true :=
  block_sound 7290 16 node edge_part_7290_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7226Part04
