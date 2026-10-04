import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 4906 through 4921. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4794Part07

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_4906_checked :
    (List.range 16).all (fun i => directedEdgeCheck (4906 + i)) = true := by
  decide

theorem edge_subblock_4906 (node : Nat) (lower : 4906 ≤ node)
    (upper : node < 4922) : directedEdgeCheck node = true :=
  block_sound 4906 16 node edge_part_4906_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4794Part07
