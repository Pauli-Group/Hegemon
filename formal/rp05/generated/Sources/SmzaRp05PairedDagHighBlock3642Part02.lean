import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 3674 through 3689. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3642Part02

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_3674_checked :
    (List.range 16).all (fun i => directedEdgeCheck (3674 + i)) = true := by
  decide

theorem edge_subblock_3674 (node : Nat) (lower : 3674 ≤ node)
    (upper : node < 3690) : directedEdgeCheck node = true :=
  block_sound 3674 16 node edge_part_3674_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3642Part02
