import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 7850 through 7865. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7738Part07

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_7850_checked :
    (List.range 16).all (fun i => directedEdgeCheck (7850 + i)) = true := by
  decide

theorem edge_subblock_7850 (node : Nat) (lower : 7850 ≤ node)
    (upper : node < 7866) : directedEdgeCheck node = true :=
  block_sound 7850 16 node edge_part_7850_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7738Part07
