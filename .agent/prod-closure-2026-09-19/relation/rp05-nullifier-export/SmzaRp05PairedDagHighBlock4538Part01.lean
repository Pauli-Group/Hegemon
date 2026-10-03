import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 4554 through 4569. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4538Part01

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_4554_checked :
    (List.range 16).all (fun i => directedEdgeCheck (4554 + i)) = true := by
  decide

theorem edge_subblock_4554 (node : Nat) (lower : 4554 ≤ node)
    (upper : node < 4570) : directedEdgeCheck node = true :=
  block_sound 4554 16 node edge_part_4554_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4538Part01
