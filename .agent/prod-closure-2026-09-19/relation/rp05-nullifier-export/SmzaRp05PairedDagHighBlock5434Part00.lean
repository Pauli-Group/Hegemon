import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 5434 through 5449. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5434Part00

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_5434_checked :
    (List.range 16).all (fun i => directedEdgeCheck (5434 + i)) = true := by
  decide

theorem edge_subblock_5434 (node : Nat) (lower : 5434 ≤ node)
    (upper : node < 5450) : directedEdgeCheck node = true :=
  block_sound 5434 16 node edge_part_5434_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5434Part00
