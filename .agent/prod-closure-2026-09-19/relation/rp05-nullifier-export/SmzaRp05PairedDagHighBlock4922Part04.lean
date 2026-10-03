import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 4986 through 5001. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4922Part04

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_4986_checked :
    (List.range 16).all (fun i => directedEdgeCheck (4986 + i)) = true := by
  decide

theorem edge_subblock_4986 (node : Nat) (lower : 4986 ≤ node)
    (upper : node < 5002) : directedEdgeCheck node = true :=
  block_sound 4986 16 node edge_part_4986_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4922Part04
