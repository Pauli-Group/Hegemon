import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 5594 through 5609. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5562Part02

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_5594_checked :
    (List.range 16).all (fun i => directedEdgeCheck (5594 + i)) = true := by
  decide

theorem edge_subblock_5594 (node : Nat) (lower : 5594 ≤ node)
    (upper : node < 5610) : directedEdgeCheck node = true :=
  block_sound 5594 16 node edge_part_5594_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5562Part02
