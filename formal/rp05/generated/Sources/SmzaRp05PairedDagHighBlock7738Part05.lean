import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 7818 through 7833. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7738Part05

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_7818_checked :
    (List.range 16).all (fun i => directedEdgeCheck (7818 + i)) = true := by
  decide

theorem edge_subblock_7818 (node : Nat) (lower : 7818 ≤ node)
    (upper : node < 7834) : directedEdgeCheck node = true :=
  block_sound 7818 16 node edge_part_7818_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7738Part05
