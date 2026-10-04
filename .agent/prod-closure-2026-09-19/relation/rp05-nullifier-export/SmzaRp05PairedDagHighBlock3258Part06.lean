import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 3354 through 3369. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3258Part06

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_3354_checked :
    (List.range 16).all (fun i => directedEdgeCheck (3354 + i)) = true := by
  decide

theorem edge_subblock_3354 (node : Nat) (lower : 3354 ≤ node)
    (upper : node < 3370) : directedEdgeCheck node = true :=
  block_sound 3354 16 node edge_part_3354_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3258Part06
