import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 3370 through 3385. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3258Part07

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_3370_checked :
    (List.range 16).all (fun i => directedEdgeCheck (3370 + i)) = true := by
  decide

theorem edge_subblock_3370 (node : Nat) (lower : 3370 ≤ node)
    (upper : node < 3386) : directedEdgeCheck node = true :=
  block_sound 3370 16 node edge_part_3370_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3258Part07
