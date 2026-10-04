import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 6970 through 6985. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6970Part00

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_6970_checked :
    (List.range 16).all (fun i => directedEdgeCheck (6970 + i)) = true := by
  decide

theorem edge_subblock_6970 (node : Nat) (lower : 6970 ≤ node)
    (upper : node < 6986) : directedEdgeCheck node = true :=
  block_sound 6970 16 node edge_part_6970_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6970Part00
