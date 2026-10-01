import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 4010 through 4025. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3898Part07

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_4010_checked :
    (List.range 16).all (fun i => directedEdgeCheck (4010 + i)) = true := by
  decide

theorem edge_subblock_4010 (node : Nat) (lower : 4010 ≤ node)
    (upper : node < 4026) : directedEdgeCheck node = true :=
  block_sound 4010 16 node edge_part_4010_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3898Part07
