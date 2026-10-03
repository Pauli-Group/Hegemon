import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 6794 through 6809. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6714Part05

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_6794_checked :
    (List.range 16).all (fun i => directedEdgeCheck (6794 + i)) = true := by
  decide

theorem edge_subblock_6794 (node : Nat) (lower : 6794 ≤ node)
    (upper : node < 6810) : directedEdgeCheck node = true :=
  block_sound 6794 16 node edge_part_6794_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6714Part05
