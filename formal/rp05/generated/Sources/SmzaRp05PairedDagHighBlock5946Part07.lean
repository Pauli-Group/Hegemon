import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 6058 through 6073. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5946Part07

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_6058_checked :
    (List.range 16).all (fun i => directedEdgeCheck (6058 + i)) = true := by
  decide

theorem edge_subblock_6058 (node : Nat) (lower : 6058 ≤ node)
    (upper : node < 6074) : directedEdgeCheck node = true :=
  block_sound 6058 16 node edge_part_6058_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5946Part07
