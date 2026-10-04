import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 6762 through 6777. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6714Part03

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_6762_checked :
    (List.range 16).all (fun i => directedEdgeCheck (6762 + i)) = true := by
  decide

theorem edge_subblock_6762 (node : Nat) (lower : 6762 ≤ node)
    (upper : node < 6778) : directedEdgeCheck node = true :=
  block_sound 6762 16 node edge_part_6762_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6714Part03
