import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 3386 through 3401. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3386Part00

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_3386_checked :
    (List.range 16).all (fun i => directedEdgeCheck (3386 + i)) = true := by
  decide

theorem edge_subblock_3386 (node : Nat) (lower : 3386 ≤ node)
    (upper : node < 3402) : directedEdgeCheck node = true :=
  block_sound 3386 16 node edge_part_3386_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3386Part00
