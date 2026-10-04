import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 4218 through 4233. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4154Part04

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_4218_checked :
    (List.range 16).all (fun i => directedEdgeCheck (4218 + i)) = true := by
  decide

theorem edge_subblock_4218 (node : Nat) (lower : 4218 ≤ node)
    (upper : node < 4234) : directedEdgeCheck node = true :=
  block_sound 4218 16 node edge_part_4218_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4154Part04
