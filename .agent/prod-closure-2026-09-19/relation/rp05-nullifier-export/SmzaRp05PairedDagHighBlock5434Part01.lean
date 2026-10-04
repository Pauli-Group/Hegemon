import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 5450 through 5465. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5434Part01

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_5450_checked :
    (List.range 16).all (fun i => directedEdgeCheck (5450 + i)) = true := by
  decide

theorem edge_subblock_5450 (node : Nat) (lower : 5450 ≤ node)
    (upper : node < 5466) : directedEdgeCheck node = true :=
  block_sound 5450 16 node edge_part_5450_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5434Part01
