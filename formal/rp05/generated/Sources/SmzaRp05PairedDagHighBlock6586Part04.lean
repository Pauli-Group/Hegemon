import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 6650 through 6665. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6586Part04

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_6650_checked :
    (List.range 16).all (fun i => directedEdgeCheck (6650 + i)) = true := by
  decide

theorem edge_subblock_6650 (node : Nat) (lower : 6650 ≤ node)
    (upper : node < 6666) : directedEdgeCheck node = true :=
  block_sound 6650 16 node edge_part_6650_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6586Part04
