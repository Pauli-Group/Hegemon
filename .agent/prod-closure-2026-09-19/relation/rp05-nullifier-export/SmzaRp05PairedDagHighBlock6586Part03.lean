import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 6634 through 6649. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6586Part03

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_6634_checked :
    (List.range 16).all (fun i => directedEdgeCheck (6634 + i)) = true := by
  decide

theorem edge_subblock_6634 (node : Nat) (lower : 6634 ≤ node)
    (upper : node < 6650) : directedEdgeCheck node = true :=
  block_sound 6634 16 node edge_part_6634_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6586Part03
