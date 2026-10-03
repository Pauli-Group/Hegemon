import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 5146 through 5161. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5050Part06

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_5146_checked :
    (List.range 16).all (fun i => directedEdgeCheck (5146 + i)) = true := by
  decide

theorem edge_subblock_5146 (node : Nat) (lower : 5146 ≤ node)
    (upper : node < 5162) : directedEdgeCheck node = true :=
  block_sound 5146 16 node edge_part_5146_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5050Part06
