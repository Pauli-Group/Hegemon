import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 4634 through 4649. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4538Part06

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_4634_checked :
    (List.range 16).all (fun i => directedEdgeCheck (4634 + i)) = true := by
  decide

theorem edge_subblock_4634 (node : Nat) (lower : 4634 ≤ node)
    (upper : node < 4650) : directedEdgeCheck node = true :=
  block_sound 4634 16 node edge_part_4634_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4538Part06
