import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 7018 through 7033. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6970Part03

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_7018_checked :
    (List.range 16).all (fun i => directedEdgeCheck (7018 + i)) = true := by
  decide

theorem edge_subblock_7018 (node : Nat) (lower : 7018 ≤ node)
    (upper : node < 7034) : directedEdgeCheck node = true :=
  block_sound 7018 16 node edge_part_7018_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6970Part03
