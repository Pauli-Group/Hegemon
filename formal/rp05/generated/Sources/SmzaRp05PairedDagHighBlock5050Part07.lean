import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 5162 through 5177. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5050Part07

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_5162_checked :
    (List.range 16).all (fun i => directedEdgeCheck (5162 + i)) = true := by
  decide

theorem edge_subblock_5162 (node : Nat) (lower : 5162 ≤ node)
    (upper : node < 5178) : directedEdgeCheck node = true :=
  block_sound 5162 16 node edge_part_5162_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5050Part07
