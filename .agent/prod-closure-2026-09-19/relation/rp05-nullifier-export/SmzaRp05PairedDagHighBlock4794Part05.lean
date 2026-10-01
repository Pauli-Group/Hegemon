import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 4874 through 4889. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4794Part05

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_4874_checked :
    (List.range 16).all (fun i => directedEdgeCheck (4874 + i)) = true := by
  decide

theorem edge_subblock_4874 (node : Nat) (lower : 4874 ≤ node)
    (upper : node < 4890) : directedEdgeCheck node = true :=
  block_sound 4874 16 node edge_part_4874_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4794Part05
