import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 4602 through 4617. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4538Part04

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_4602_checked :
    (List.range 16).all (fun i => directedEdgeCheck (4602 + i)) = true := by
  decide

theorem edge_subblock_4602 (node : Nat) (lower : 4602 ≤ node)
    (upper : node < 4618) : directedEdgeCheck node = true :=
  block_sound 4602 16 node edge_part_4602_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4538Part04
