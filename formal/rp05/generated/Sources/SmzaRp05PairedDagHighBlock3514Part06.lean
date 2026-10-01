import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 3610 through 3625. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3514Part06

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_3610_checked :
    (List.range 16).all (fun i => directedEdgeCheck (3610 + i)) = true := by
  decide

theorem edge_subblock_3610 (node : Nat) (lower : 3610 ≤ node)
    (upper : node < 3626) : directedEdgeCheck node = true :=
  block_sound 3610 16 node edge_part_3610_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3514Part06
