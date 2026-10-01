import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 7834 through 7849. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7738Part06

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_7834_checked :
    (List.range 16).all (fun i => directedEdgeCheck (7834 + i)) = true := by
  decide

theorem edge_subblock_7834 (node : Nat) (lower : 7834 ≤ node)
    (upper : node < 7850) : directedEdgeCheck node = true :=
  block_sound 7834 16 node edge_part_7834_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7738Part06
