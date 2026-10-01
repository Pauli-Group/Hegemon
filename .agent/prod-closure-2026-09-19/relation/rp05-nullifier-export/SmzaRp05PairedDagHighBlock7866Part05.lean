import SmzaRp05PairedDagEdgeSupport

/-! Exact 5-node directed-edge check for current/reference DAG nodes 7946 through 7950. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7866Part05

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_7946_checked :
    (List.range 5).all (fun i => directedEdgeCheck (7946 + i)) = true := by
  decide

theorem edge_subblock_7946 (node : Nat) (lower : 7946 ≤ node)
    (upper : node < 7951) : directedEdgeCheck node = true :=
  block_sound 7946 5 node edge_part_7946_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7866Part05
