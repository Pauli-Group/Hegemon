import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 7786 through 7801. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7738Part03

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_7786_checked :
    (List.range 16).all (fun i => directedEdgeCheck (7786 + i)) = true := by
  decide

theorem edge_subblock_7786 (node : Nat) (lower : 7786 ≤ node)
    (upper : node < 7802) : directedEdgeCheck node = true :=
  block_sound 7786 16 node edge_part_7786_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7738Part03
