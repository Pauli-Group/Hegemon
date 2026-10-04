import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 7210 through 7225. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7098Part07

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_7210_checked :
    (List.range 16).all (fun i => directedEdgeCheck (7210 + i)) = true := by
  decide

theorem edge_subblock_7210 (node : Nat) (lower : 7210 ≤ node)
    (upper : node < 7226) : directedEdgeCheck node = true :=
  block_sound 7210 16 node edge_part_7210_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7098Part07
