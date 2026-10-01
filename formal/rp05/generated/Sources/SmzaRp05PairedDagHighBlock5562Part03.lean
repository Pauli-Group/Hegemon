import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 5610 through 5625. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5562Part03

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_5610_checked :
    (List.range 16).all (fun i => directedEdgeCheck (5610 + i)) = true := by
  decide

theorem edge_subblock_5610 (node : Nat) (lower : 5610 ≤ node)
    (upper : node < 5626) : directedEdgeCheck node = true :=
  block_sound 5610 16 node edge_part_5610_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5562Part03
