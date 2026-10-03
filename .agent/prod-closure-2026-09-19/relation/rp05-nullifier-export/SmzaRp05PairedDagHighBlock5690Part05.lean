import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 5770 through 5785. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5690Part05

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_5770_checked :
    (List.range 16).all (fun i => directedEdgeCheck (5770 + i)) = true := by
  decide

theorem edge_subblock_5770 (node : Nat) (lower : 5770 ≤ node)
    (upper : node < 5786) : directedEdgeCheck node = true :=
  block_sound 5770 16 node edge_part_5770_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5690Part05
