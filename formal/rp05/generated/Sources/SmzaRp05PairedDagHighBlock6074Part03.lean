import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 6122 through 6137. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6074Part03

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_6122_checked :
    (List.range 16).all (fun i => directedEdgeCheck (6122 + i)) = true := by
  decide

theorem edge_subblock_6122 (node : Nat) (lower : 6122 ≤ node)
    (upper : node < 6138) : directedEdgeCheck node = true :=
  block_sound 6122 16 node edge_part_6122_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6074Part03
