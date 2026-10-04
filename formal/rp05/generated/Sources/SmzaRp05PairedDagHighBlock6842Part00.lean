import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 6842 through 6857. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6842Part00

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_6842_checked :
    (List.range 16).all (fun i => directedEdgeCheck (6842 + i)) = true := by
  decide

theorem edge_subblock_6842 (node : Nat) (lower : 6842 ≤ node)
    (upper : node < 6858) : directedEdgeCheck node = true :=
  block_sound 6842 16 node edge_part_6842_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6842Part00
