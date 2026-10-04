import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 5658 through 5673. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5562Part06

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_5658_checked :
    (List.range 16).all (fun i => directedEdgeCheck (5658 + i)) = true := by
  decide

theorem edge_subblock_5658 (node : Nat) (lower : 5658 ≤ node)
    (upper : node < 5674) : directedEdgeCheck node = true :=
  block_sound 5658 16 node edge_part_5658_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5562Part06
