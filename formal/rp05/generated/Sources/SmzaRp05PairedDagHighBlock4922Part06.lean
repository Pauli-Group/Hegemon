import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 5018 through 5033. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4922Part06

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_5018_checked :
    (List.range 16).all (fun i => directedEdgeCheck (5018 + i)) = true := by
  decide

theorem edge_subblock_5018 (node : Nat) (lower : 5018 ≤ node)
    (upper : node < 5034) : directedEdgeCheck node = true :=
  block_sound 5018 16 node edge_part_5018_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4922Part06
