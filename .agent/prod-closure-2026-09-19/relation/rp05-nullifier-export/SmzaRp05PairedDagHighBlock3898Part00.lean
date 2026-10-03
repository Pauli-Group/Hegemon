import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 3898 through 3913. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3898Part00

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_3898_checked :
    (List.range 16).all (fun i => directedEdgeCheck (3898 + i)) = true := by
  decide

theorem edge_subblock_3898 (node : Nat) (lower : 3898 ≤ node)
    (upper : node < 3914) : directedEdgeCheck node = true :=
  block_sound 3898 16 node edge_part_3898_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3898Part00
