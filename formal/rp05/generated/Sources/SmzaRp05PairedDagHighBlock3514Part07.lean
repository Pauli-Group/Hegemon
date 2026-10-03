import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 3626 through 3641. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3514Part07

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_3626_checked :
    (List.range 16).all (fun i => directedEdgeCheck (3626 + i)) = true := by
  decide

theorem edge_subblock_3626 (node : Nat) (lower : 3626 ≤ node)
    (upper : node < 3642) : directedEdgeCheck node = true :=
  block_sound 3626 16 node edge_part_3626_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3514Part07
