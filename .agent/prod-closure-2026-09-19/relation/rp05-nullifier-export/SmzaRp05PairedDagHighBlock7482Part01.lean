import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 7498 through 7513. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7482Part01

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_7498_checked :
    (List.range 16).all (fun i => directedEdgeCheck (7498 + i)) = true := by
  decide

theorem edge_subblock_7498 (node : Nat) (lower : 7498 ≤ node)
    (upper : node < 7514) : directedEdgeCheck node = true :=
  block_sound 7498 16 node edge_part_7498_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7482Part01
