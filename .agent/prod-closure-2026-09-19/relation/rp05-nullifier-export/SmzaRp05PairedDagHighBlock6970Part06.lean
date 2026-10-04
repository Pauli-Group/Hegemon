import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 7066 through 7081. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6970Part06

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_7066_checked :
    (List.range 16).all (fun i => directedEdgeCheck (7066 + i)) = true := by
  decide

theorem edge_subblock_7066 (node : Nat) (lower : 7066 ≤ node)
    (upper : node < 7082) : directedEdgeCheck node = true :=
  block_sound 7066 16 node edge_part_7066_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6970Part06
