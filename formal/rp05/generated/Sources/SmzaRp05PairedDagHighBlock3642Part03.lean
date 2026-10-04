import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 3690 through 3705. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3642Part03

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_3690_checked :
    (List.range 16).all (fun i => directedEdgeCheck (3690 + i)) = true := by
  decide

theorem edge_subblock_3690 (node : Nat) (lower : 3690 ≤ node)
    (upper : node < 3706) : directedEdgeCheck node = true :=
  block_sound 3690 16 node edge_part_3690_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3642Part03
