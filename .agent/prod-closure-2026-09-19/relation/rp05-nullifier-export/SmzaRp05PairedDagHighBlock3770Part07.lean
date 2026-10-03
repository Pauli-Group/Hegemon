import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 3882 through 3897. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3770Part07

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_3882_checked :
    (List.range 16).all (fun i => directedEdgeCheck (3882 + i)) = true := by
  decide

theorem edge_subblock_3882 (node : Nat) (lower : 3882 ≤ node)
    (upper : node < 3898) : directedEdgeCheck node = true :=
  block_sound 3882 16 node edge_part_3882_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3770Part07
