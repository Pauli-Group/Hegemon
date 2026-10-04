import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 5530 through 5545. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5434Part06

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_5530_checked :
    (List.range 16).all (fun i => directedEdgeCheck (5530 + i)) = true := by
  decide

theorem edge_subblock_5530 (node : Nat) (lower : 5530 ≤ node)
    (upper : node < 5546) : directedEdgeCheck node = true :=
  block_sound 5530 16 node edge_part_5530_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5434Part06
