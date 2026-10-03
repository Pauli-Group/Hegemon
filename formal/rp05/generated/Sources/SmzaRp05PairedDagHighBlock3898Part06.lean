import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 3994 through 4009. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3898Part06

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_3994_checked :
    (List.range 16).all (fun i => directedEdgeCheck (3994 + i)) = true := by
  decide

theorem edge_subblock_3994 (node : Nat) (lower : 3994 ≤ node)
    (upper : node < 4010) : directedEdgeCheck node = true :=
  block_sound 3994 16 node edge_part_3994_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3898Part06
