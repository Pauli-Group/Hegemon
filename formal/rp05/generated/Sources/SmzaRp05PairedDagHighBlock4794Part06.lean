import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 4890 through 4905. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4794Part06

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_4890_checked :
    (List.range 16).all (fun i => directedEdgeCheck (4890 + i)) = true := by
  decide

theorem edge_subblock_4890 (node : Nat) (lower : 4890 ≤ node)
    (upper : node < 4906) : directedEdgeCheck node = true :=
  block_sound 4890 16 node edge_part_4890_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4794Part06
