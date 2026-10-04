import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 5402 through 5417. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5306Part06

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_5402_checked :
    (List.range 16).all (fun i => directedEdgeCheck (5402 + i)) = true := by
  decide

theorem edge_subblock_5402 (node : Nat) (lower : 5402 ≤ node)
    (upper : node < 5418) : directedEdgeCheck node = true :=
  block_sound 5402 16 node edge_part_5402_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5306Part06
