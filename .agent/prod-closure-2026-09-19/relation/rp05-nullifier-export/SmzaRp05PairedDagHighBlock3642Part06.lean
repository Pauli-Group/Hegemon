import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 3738 through 3753. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3642Part06

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_3738_checked :
    (List.range 16).all (fun i => directedEdgeCheck (3738 + i)) = true := by
  decide

theorem edge_subblock_3738 (node : Nat) (lower : 3738 ≤ node)
    (upper : node < 3754) : directedEdgeCheck node = true :=
  block_sound 3738 16 node edge_part_3738_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3642Part06
