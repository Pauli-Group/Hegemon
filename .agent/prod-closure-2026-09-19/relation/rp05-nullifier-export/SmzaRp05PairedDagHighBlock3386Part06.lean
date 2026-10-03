import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 3482 through 3497. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3386Part06

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_3482_checked :
    (List.range 16).all (fun i => directedEdgeCheck (3482 + i)) = true := by
  decide

theorem edge_subblock_3482 (node : Nat) (lower : 3482 ≤ node)
    (upper : node < 3498) : directedEdgeCheck node = true :=
  block_sound 3482 16 node edge_part_3482_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3386Part06
