import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 4074 through 4089. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4026Part03

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_4074_checked :
    (List.range 16).all (fun i => directedEdgeCheck (4074 + i)) = true := by
  decide

theorem edge_subblock_4074 (node : Nat) (lower : 4074 ≤ node)
    (upper : node < 4090) : directedEdgeCheck node = true :=
  block_sound 4074 16 node edge_part_4074_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4026Part03
