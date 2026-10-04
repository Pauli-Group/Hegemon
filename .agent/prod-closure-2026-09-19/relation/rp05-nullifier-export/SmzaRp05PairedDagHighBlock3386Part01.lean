import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 3402 through 3417. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3386Part01

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_3402_checked :
    (List.range 16).all (fun i => directedEdgeCheck (3402 + i)) = true := by
  decide

theorem edge_subblock_3402 (node : Nat) (lower : 3402 ≤ node)
    (upper : node < 3418) : directedEdgeCheck node = true :=
  block_sound 3402 16 node edge_part_3402_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3386Part01
