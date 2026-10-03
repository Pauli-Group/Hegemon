import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 4170 through 4185. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4154Part01

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_4170_checked :
    (List.range 16).all (fun i => directedEdgeCheck (4170 + i)) = true := by
  decide

theorem edge_subblock_4170 (node : Nat) (lower : 4170 ≤ node)
    (upper : node < 4186) : directedEdgeCheck node = true :=
  block_sound 4170 16 node edge_part_4170_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4154Part01
