import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 4314 through 4329. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4282Part02

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_4314_checked :
    (List.range 16).all (fun i => directedEdgeCheck (4314 + i)) = true := by
  decide

theorem edge_subblock_4314 (node : Nat) (lower : 4314 ≤ node)
    (upper : node < 4330) : directedEdgeCheck node = true :=
  block_sound 4314 16 node edge_part_4314_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4282Part02
